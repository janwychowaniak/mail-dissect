"""Assembling the response: artifacts, bodies, flags (SPEC §5, §8, §13).

This is where the dissection meets the environment — the artifact store, and from stage 5 the
optional tools and the deadline. Everything above it (`message.py` and below) is a pure
function of the input bytes.
"""

from __future__ import annotations

import dataclasses

from .artifacts import ArtifactStore
from .decode import hash_bytes
from .htmlscan import AnchorEvent, HtmlScan, ResourceEvent, TextEvent, scan_html
from .message import ParsedMessage, dissect_messages
from .mimetree import PartInfo
from .models import (
    AddressOut,
    ArtifactOut,
    AttachmentOut,
    AuthResultOut,
    BodyOut,
    DissectResponse,
    Flag,
    LinkOut,
    MessageOut,
    MimePartOut,
    ObservableOut,
    ObservableSourceOut,
    ReceivedOut,
    ResourceOut,
    SourceHashes,
    scrub_surrogates,
)
from .observables import Collector, Source
from .registries import Registries
from .settings import Settings
from .unwrap import Unwrapper
from .urls import UrlParts, split

_FLAG_ORDER: tuple[Flag, ...] = (
    "truncated",
    "malformed_mime",
    "encoding_fallback",
    "attachment_unreadable",
    "artifact_store_failed",
)


class _Assembly:
    """Collects the artifacts and flags of one dissection while the messages are built."""

    def __init__(self, store: ArtifactStore, dissect_id: str, settings: Settings) -> None:
        self._store = store
        self._dissect_id = dissect_id
        self._settings = settings
        self.unwrapper = Unwrapper(settings.unwrappers)
        self.registries: Registries | None = None
        self.artifacts: list[ArtifactOut] = []
        self.flags: set[str] = set()
        self.scrubbed = False

    def store_artifact(
        self,
        kind: str,
        data: bytes,
        *,
        message_index: int,
        part_index: int | None = None,
        filename: str,
        mime: str = "application/octet-stream",
    ) -> str | None:
        reference = self._store.put(
            self._dissect_id,
            kind,  # type: ignore[arg-type]
            data,
            message_index=message_index,
            part_index=part_index,
            filename=filename,
            mime=mime,
        )
        if reference is None:
            self.flags.add("artifact_store_failed")
            return None
        self.artifacts.append(ArtifactOut(**dataclasses.asdict(reference)))
        return reference.artifact_id

    def text(self, value: str) -> str:
        cleaned, changed = scrub_surrogates(value)
        if changed:
            # [D20]: what is returned is no longer what stood in the material, so say so.
            self.flags.add("encoding_fallback")
            self.scrubbed = True
        return cleaned


def build_response(
    raw: bytes,
    dissect_id: str,
    store: ArtifactStore,
    settings: Settings,
    registries: Registries,
) -> DissectResponse:
    """Dissect the input and assemble the answer."""
    dissection = dissect_messages(
        raw,
        max_attachment_bytes=settings.max_attachment_bytes,
        max_parts=settings.max_mime_parts,
        max_depth=settings.max_nesting_depth,
    )
    assembly = _Assembly(store, dissect_id, settings)
    assembly.registries = registries
    assembly.flags |= dissection.flags

    messages = [_build_message(parsed, assembly, settings) for parsed in dissection.messages]
    digests = hash_bytes(raw)
    ordered = [flag for flag in _FLAG_ORDER if flag in assembly.flags]
    return DissectResponse(
        dissect_id=dissect_id,
        source=SourceHashes(
            size=len(raw), md5=digests.md5, sha1=digests.sha1, sha256=digests.sha256
        ),
        messages=messages,
        artifacts=assembly.artifacts,
        flags=ordered,
    )


def _build_message(parsed: ParsedMessage, assembly: _Assembly, settings: Settings) -> MessageOut:
    index = parsed.index
    # [D12]: the eml artifact carries the bytes that were in the input.
    assembly.store_artifact("eml", parsed.raw, message_index=index, filename=f"message-{index}.eml")
    header_block = parsed.raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    assembly.store_artifact(
        "headers", header_block, message_index=index, filename=f"headers-{index}.txt"
    )

    scan = _scan_body_html(parsed)
    cid_map = _cid_map(parsed)
    body = _build_body(parsed, assembly, settings, scan)
    links, resources = _build_addresses(scan, assembly, cid_map)
    observables = _build_observables(parsed, assembly, scan, cid_map)
    return MessageOut(
        index=index,
        depth=parsed.depth,
        headers={
            name: [assembly.text(value) for value in values]
            for name, values in parsed.headers.items()
        },
        addresses={
            name: [
                AddressOut(
                    display_name=assembly.text(entry.display_name) if entry.display_name else None,
                    address=assembly.text(entry.address) if entry.address else None,
                    local_part=assembly.text(entry.local_part) if entry.local_part else None,
                    domain=assembly.text(entry.domain) if entry.domain else None,
                )
                for entry in entries
            ]
            for name, entries in parsed.addresses.items()
        },
        auth=[
            AuthResultOut(method=item.method, result=item.result, params=item.params)
            for item in parsed.auth
        ],
        received=[
            ReceivedOut(
                from_host=hop.from_host,
                from_ip=hop.from_ip,
                by_host=hop.by_host,
                with_=hop.with_,
                id=hop.id,
                for_=hop.for_,
                timestamp=hop.timestamp,
            )
            for hop in parsed.received
        ],
        body=body,
        mime_parts=[_build_part(info, assembly) for info in parsed.tree.parts],
        links=links,
        resources=resources,
        observables=observables,
        attachments=[
            _build_attachment(parsed.tree.parts[part_index], assembly, index)
            for part_index in parsed.tree.attachments
        ],
    )


def _build_observables(
    parsed: ParsedMessage, assembly: _Assembly, scan: HtmlScan | None, cid_map: dict[str, int]
) -> list[ObservableOut]:
    """Scan this message in the order of `[D9]`: headers, then text, then HTML.

    The collector is append-only, so candidates that a later stage adds from document text
    can only extend the tail - the deterministic core of the list does not move when the
    text extractor is absent or fails (test 62).
    """
    assert assembly.registries is not None
    collector = Collector(assembly.registries)

    for name, values in parsed.headers.items():
        for index, value in enumerate(values):
            collector.feed_text(value, Source(kind="header", header_name=name, header_index=index))

    text_index = parsed.tree.body_text_index
    if text_index is not None:
        info = parsed.tree.parts[text_index]
        if info.text:
            collector.feed_text(info.text.text, Source(kind="body_text", part_index=text_index))

    html_index = parsed.tree.body_html_index
    if scan is not None and html_index is not None:
        source = Source(kind="body_html", part_index=html_index)
        for event in scan.events:
            if isinstance(event, TextEvent):
                collector.feed_text(event.text, source)
            elif isinstance(event, AnchorEvent | ResourceEvent):
                # The address as the consumer will see it in links[]/resources[]: unwrapped,
                # so the two lists and this one describe the same thing (SPEC §11).
                collector.feed_url(assembly.unwrapper.apply(event.href).href, source)

    return [
        ObservableOut(
            value=assembly.text(candidate.value),
            value_raw=assembly.text(candidate.value_raw),
            type=candidate.type,
            subtype=candidate.subtype,
            defanged=candidate.defanged,
            ambiguous=candidate.ambiguous,
            occurrences=candidate.occurrences,
            sources=[
                ObservableSourceOut(
                    kind=source.kind,
                    header_name=source.header_name,
                    header_index=source.header_index,
                    part_index=source.part_index,
                )
                for source in candidate.sources
            ],
        )
        for candidate in collector.finish()
    ]


def _build_part(info: PartInfo, assembly: _Assembly) -> MimePartOut:
    return MimePartOut(
        content_type=info.content_type,
        disposition=info.disposition,
        filename=assembly.text(info.filename) if info.filename else None,
        content_id=info.content_id,
        size=info.size,
        charset_declared=info.charset_declared,
        charset_used=info.charset_used,
        transfer_encoding=info.transfer_encoding,
    )


def _build_attachment(info: PartInfo, assembly: _Assembly, message_index: int) -> AttachmentOut:
    artifact_id = None
    if info.payload is not None:
        artifact_id = assembly.store_artifact(
            "attachment",
            info.payload,
            message_index=message_index,
            part_index=info.index,
            filename=info.filename or f"part-{info.index}.bin",
        )
    name = assembly.text(info.filename) if info.filename else None
    extension = None
    if name and "." in name:
        extension = name.rsplit(".", 1)[-1].lower() or None
    return AttachmentOut(
        part_index=info.index,
        artifact_id=artifact_id,
        text_artifact_id=None,  # filled in stage 5, when the text extractor is wired
        filename=name,
        extension=extension,
        disposition=info.disposition,
        content_id=info.content_id,
        declared_mime=info.content_type,
        detected_mime=info.detected_mime,
        size=info.size,
        md5=info.hashes.md5 if info.hashes else None,
        sha1=info.hashes.sha1 if info.hashes else None,
        sha256=info.hashes.sha256 if info.hashes else None,
    )


def _scan_body_html(parsed: ParsedMessage) -> HtmlScan | None:
    """One scan of the HTML body, shared by everything derived from it (SPEC §9)."""
    index = parsed.tree.body_html_index
    if index is None:
        return None
    info = parsed.tree.parts[index]
    return scan_html(info.text.text) if info.text else None


def _cid_map(parsed: ParsedMessage) -> dict[str, int]:
    """`Content-ID` to part index, within THIS message only (RFC 2392, exact match)."""
    mapping: dict[str, int] = {}
    for info in parsed.tree.parts:
        if info.content_id:
            mapping.setdefault(info.content_id.strip().strip("<>"), info.index)
    return mapping


def _url_fields(href: str, assembly: _Assembly, cid_map: dict[str, int]) -> dict[str, object]:
    """Unwrap first, then decompose: the fields describe the TARGET, not the wrapper (§10)."""
    unwrapped = assembly.unwrapper.apply(href)
    parts: UrlParts = split(unwrapped.href)
    cid_part = None
    if parts.scheme == "cid" and parts.path:
        cid_part = cid_map.get(parts.path.strip().strip("<>"))
    return {
        "href": assembly.text(parts.href),
        "scheme": parts.scheme,
        "host": parts.host,
        "port": parts.port,
        "userinfo": assembly.text(parts.userinfo) if parts.userinfo else None,
        "path": assembly.text(parts.path) if parts.path else None,
        "query": assembly.text(parts.query) if parts.query else None,
        "fragment": assembly.text(parts.fragment) if parts.fragment else None,
        "host_idn": parts.host_idn,
        "host_punycode": parts.host_punycode,
        "rewritten_from": assembly.text(unwrapped.rewritten_from)
        if unwrapped.rewritten_from
        else None,
        "unwrap_failed": unwrapped.failed,
        "cid_part": cid_part,
    }


def _build_addresses(
    scan: HtmlScan | None, assembly: _Assembly, cid_map: dict[str, int]
) -> tuple[list[LinkOut], list[ResourceOut]]:
    """Anchors and auto-loaded resources, in document order, as two disjoint lists (§9.1)."""
    links: list[LinkOut] = []
    resources: list[ResourceOut] = []
    if scan is None:
        return links, resources
    for event in scan.events:
        if isinstance(event, AnchorEvent):
            fields = _url_fields(event.href, assembly, cid_map)
            links.append(
                LinkOut(text=assembly.text(event.text) if event.text else None, **fields)  # type: ignore[arg-type]
            )
        elif isinstance(event, ResourceEvent):
            fields = _url_fields(event.href, assembly, cid_map)
            resources.append(ResourceOut(element=event.element, **fields))  # type: ignore[arg-type]
    return links, resources


def _build_body(
    parsed: ParsedMessage, assembly: _Assembly, settings: Settings, scan: HtmlScan | None = None
) -> BodyOut:
    """Each representation has its own threshold and its own link (SPEC §8, [D4])."""
    body = BodyOut(
        text_part_index=parsed.tree.body_text_index,
        html_part_index=parsed.tree.body_html_index,
    )
    for attribute, part_index, kind, name in (
        ("text", parsed.tree.body_text_index, "body_text", "body.txt"),
        ("html", parsed.tree.body_html_index, "body_html", "body.html"),
    ):
        if part_index is None:
            continue
        info = parsed.tree.parts[part_index]
        if info.text is None:
            continue
        content = assembly.text(info.text.text)
        encoded = content.encode("utf-8")
        artifact_id = assembly.store_artifact(
            kind,
            encoded,
            message_index=parsed.index,
            part_index=part_index,
            filename=f"{parsed.index}-{name}",
        )
        setattr(body, f"{attribute}_artifact_id", artifact_id)
        # Above the threshold the content lives only in the artifact - unless storing it
        # failed, in which case a large response beats losing the content (SPEC §8).
        if len(encoded) <= settings.max_inline_body_bytes or artifact_id is None:
            setattr(body, attribute, content)

    if scan is not None:
        # [D4]: the text derived from HTML is a representation like the other two, with its
        # own threshold and its own link. A consumer cannot reproduce it from the body_html
        # artifact, because the conversion is a rule of this service, not their job.
        derived = assembly.text(scan.text())
        encoded = derived.encode("utf-8")
        artifact_id = assembly.store_artifact(
            "body_text_from_html",
            encoded,
            message_index=parsed.index,
            part_index=parsed.tree.body_html_index,
            filename=f"{parsed.index}-body-from-html.txt",
        )
        body.text_from_html_artifact_id = artifact_id
        if len(encoded) <= settings.max_inline_body_bytes or artifact_id is None:
            body.text_from_html = derived
    return body
