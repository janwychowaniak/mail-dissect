"""The MIME tree: parts, their indices, and which of them are the body (SPEC §6).

The tree itself comes from the standard library with `policy.compat32` `[D11]` — it is
battle-tested and ten times cheaper per part than `policy.default` (F3). Two things it cannot
do are done here: the bytes of a nested message are located in the input rather than rebuilt
`[D12]`, and a `message/rfc822` part that carries a transfer encoding is decoded and parsed
recursively, because the standard library turns it into a bogus `text/plain` child under both
policies and says nothing (F2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email.message import Message
from email.parser import BytesParser
from io import BytesIO

from . import spans
from .decode import Hashes, TextResult, decode_text, decode_transfer, hash_bytes
from .headers import COMPAT32_TEXT, filename_of
from .sniff import detect_mime


@dataclass(slots=True)
class PartInfo:
    """One entry of `mime_parts[]`; its position in the list is its only identifier (§5.2)."""

    index: int
    content_type: str
    disposition: str | None = None
    filename: str | None = None
    content_id: str | None = None
    size: int = 0
    charset_declared: str | None = None
    charset_used: str | None = None
    transfer_encoding: str | None = None
    is_container: bool = False
    payload: bytes | None = None
    hashes: Hashes | None = None
    detected_mime: str | None = None
    text: TextResult | None = None
    nested_bytes: bytes | None = None
    unreadable: bool = False
    oversize: bool = False


@dataclass(slots=True)
class Tree:
    parts: list[PartInfo] = field(default_factory=list)
    # True when WE cut the input to keep the cost bounded. What the parser then reports about
    # the missing end of the message describes our cut, not the material, so it must not be
    # read as `malformed_mime` (SPEC §17: that flag describes the material).
    cut: bool = False
    body_text_index: int | None = None
    body_html_index: int | None = None
    attachments: list[int] = field(default_factory=list)
    nested: list[int] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)


def parse_tree(raw: bytes, *, max_attachment_bytes: int, max_parts: int) -> Tree:
    """Walk the message once, in document order, assigning the indices used everywhere."""
    tree = Tree()
    # [D13]: the limit is established BEFORE the tree is built. Stopping the walk instead
    # would bound the result while the parser had already done all of the work - which on a
    # message of a million small parts is the whole cost (F3).
    if spans.estimate(raw, max_parts, max_parts).over_parts:
        raw = spans.cut_to_part_limit(raw, max_parts)
        tree.flags.add("truncated")
        tree.cut = True
    message = BytesParser(policy=COMPAT32_TEXT).parsebytes(raw)
    _visit(message, raw, _root_region(raw), tree, max_attachment_bytes, max_parts)

    for info in tree.parts:
        if info.is_container or info.index in (tree.body_text_index, tree.body_html_index):
            continue
        # An attachment is any part that is not a container and was not chosen as the body
        # (SPEC §6.3). No Content-Disposition criterion: the entry carries `disposition` and
        # `content_id`, and filtering is the consumer's business.
        tree.attachments.append(info.index)
    return tree


def _root_region(raw: bytes) -> tuple[int, int]:
    return (0, len(raw))


def _visit(
    part: Message,
    raw: bytes,
    region: tuple[int, int],
    tree: Tree,
    max_attachment_bytes: int,
    max_parts: int,
) -> None:
    if len(tree.parts) >= max_parts:
        tree.flags.add("truncated")
        return

    content_type = part.get_content_type()
    filename, filename_fell_back = filename_of(part)
    if filename_fell_back:
        tree.flags.add("encoding_fallback")
    info = PartInfo(
        index=len(tree.parts),
        content_type=content_type,
        disposition=part.get_content_disposition(),
        filename=filename,
        content_id=(part.get("content-id") or "").strip() or None,
        charset_declared=_declared_charset(part),
        transfer_encoding=(part.get("content-transfer-encoding") or "").strip().lower() or None,
    )
    tree.parts.append(info)
    if part.defects and not tree.cut:
        # The parser's own report of damage. Suppressed when we did the cutting ourselves:
        # a missing end of message then describes our limit, not the material (SPEC §17).
        tree.flags.add("malformed_mime")

    if _is_container(part):
        info.is_container = True
        boundary = part.get_boundary()
        children = part.get_payload()
        assert isinstance(children, list)
        blocks = (
            spans.part_blocks(raw, boundary.encode("latin-1", "replace"), region=region)
            if boundary
            else []
        )
        if len(blocks) != len(children) and not tree.cut:
            # Our view of the raw bytes and the parser's view of the tree disagree; the parts
            # are still dissected, but nothing that depends on byte spans may be trusted.
            tree.flags.add("malformed_mime")
        for ordinal, child in enumerate(children):
            child_region = blocks[ordinal] if ordinal < len(blocks) else region
            _visit(child, raw, child_region, tree, max_attachment_bytes, max_parts)
        return

    body_start, body_end = spans.body_span(raw, *region)
    if content_type == "message/rfc822":
        _read_nested(info, part, raw, (body_start, body_end), tree)
        return

    _read_leaf(info, raw[body_start:body_end], tree, max_attachment_bytes)
    _select_body(info, tree)


def _is_container(part: Message) -> bool:
    """A container is a part that actually segmented into children.

    Structure, not declaration: a `multipart/*` whose boundary never appears is a leaf, and
    `message/rfc822` is always a leaf here — its children belong to its own message (§6.1).
    """
    if part.get_content_type() == "message/rfc822":
        return False
    payload = part.get_payload()
    return isinstance(payload, list) and len(payload) > 0


def _declared_charset(part: Message) -> str | None:
    charset = part.get_param("charset")
    return str(charset).strip() or None if charset else None


def _read_nested(
    info: PartInfo, part: Message, raw: bytes, body: tuple[int, int], tree: Tree
) -> None:
    """Take the nested message's ORIGINAL bytes out of the input `[D12]`."""
    located = raw[body[0] : body[1]]
    encoding = info.transfer_encoding
    encoded = encoding not in (None, "7bit", "8bit", "binary")
    if encoded:
        # F2: the standard library has already mis-parsed this part into a text child, so the
        # decoded span is the only correct source for what the nested message is.
        decoded, damaged = decode_transfer(located, encoding)
        if damaged or decoded is None:
            tree.flags.add("malformed_mime")
        located = decoded if decoded is not None else b""
    elif not _verifies(located, part):
        # The locator is self-checking: a span is accepted only when re-parsing it gives the
        # structure the standard library reported. Re-serialising is the fallback, and it is
        # not byte-neutral (F1), so the result is marked rather than passed off as original.
        tree.flags.add("malformed_mime")
        located = _reserialise(part)
    info.nested_bytes = located
    info.payload = located
    info.size = len(located)
    info.hashes = hash_bytes(located)
    info.detected_mime = "message/rfc822"
    tree.nested.append(info.index)


def _verifies(located: bytes, part: Message) -> bool:
    """Does the located span parse into the same shape the standard library reported?"""
    children = part.get_payload()
    if not isinstance(children, list) or len(children) != 1:
        return False
    expected = children[0]
    if not isinstance(expected, Message):
        return False
    try:
        actual = BytesParser(policy=COMPAT32_TEXT).parsebytes(located)
    except Exception:
        return False
    if actual.get_content_type() != expected.get_content_type():
        return False
    actual_children = actual.get_payload()
    expected_children = expected.get_payload()
    if isinstance(expected_children, list) != isinstance(actual_children, list):
        return False
    if isinstance(expected_children, list) and isinstance(actual_children, list):
        return len(expected_children) == len(actual_children)
    return True


def _reserialise(part: Message) -> bytes:
    from email.generator import BytesGenerator
    from email.policy import SMTP

    children = part.get_payload()
    if not isinstance(children, list) or not children:
        return b""
    inner = children[0]
    if not isinstance(inner, Message):
        return b""
    buffer = BytesIO()
    # typeshed types `flatten` for EmailMessage; compat32 hands us a Message, which is what
    # the generator has always accepted and what this fallback is for.
    BytesGenerator(buffer, policy=SMTP).flatten(inner)  # type: ignore[arg-type]
    return buffer.getvalue()


def _read_leaf(info: PartInfo, raw_payload: bytes, tree: Tree, max_attachment_bytes: int) -> None:
    """Read a leaf's bytes from the INPUT, not from the parsed object.

    `get_payload(decode=False)` hands back a `str` that the parser produced with
    surrogateescape, and re-encoding it loses every byte above 0x7F — which is precisely the
    material that makes `charset_declared` differ from `charset_used`. The span is the
    message as it arrived, so the hashes and the text both describe what was really there.
    """
    decoded, damaged = decode_transfer(raw_payload, info.transfer_encoding)
    if decoded is None:
        # Not "too large" but "cannot be read": the two are different events with different
        # flags, so the consumer can tell a limit from damage (SPEC §15).
        info.unreadable = True
        tree.flags.add("attachment_unreadable")
        return
    if damaged:
        tree.flags.add("malformed_mime")

    info.hashes = hash_bytes(decoded)
    info.size = info.hashes.size
    info.detected_mime = detect_mime(decoded[:4096])

    if info.size > max_attachment_bytes:
        # The material was healthy; the service chose not to go further. The hashes stay, so
        # the consumer can identify a file we do not serve (SPEC §15).
        info.oversize = True
        tree.flags.add("truncated")
        return

    info.payload = decoded
    if info.content_type.startswith("text/"):
        result = decode_text(
            decoded, info.charset_declared, is_html=info.content_type == "text/html"
        )
        info.text = result
        info.charset_used = result.charset_used
        if result.fallback:
            tree.flags.add("encoding_fallback")


def _select_body(info: PartInfo, tree: Tree) -> None:
    """The first `text/plain` and the first `text/html` leaf, in document order (SPEC §6.3).

    One rule, no `multipart/alternative` special case and no `Content-Disposition` criterion.
    The choice is reported in `body.text_part_index` / `body.html_part_index`, so a consumer
    who would choose differently has everything needed to do so.
    """
    if info.text is None:
        return
    if info.content_type == "text/plain" and tree.body_text_index is None:
        tree.body_text_index = info.index
    elif info.content_type == "text/html" and tree.body_html_index is None:
        tree.body_html_index = info.index
