"""Decoding: transport encoding first, then characters (SPEC §7.2).

Everything the service reads is read from the DECODED content of a part, never from raw
bytes: `quoted-printable` breaks long URLs with `=CRLF` in the middle, so a regular
expression run over a raw message returns truncated garbage. That applies to every URL, not
to special cases.

The charset ladder is fixed so that two implementations agree, and it is deliberately not a
statistical detector: those change their verdicts between library versions, which would make
the determinism criterion depend on a third registry version.
"""

from __future__ import annotations

import binascii
import codecs
import hashlib
import quopri
import re
from base64 import b64decode
from dataclasses import dataclass

_META_CHARSET = re.compile(
    rb"""<meta[^>]+charset\s*=\s*["']?\s*([A-Za-z0-9_.:+-]+)""", re.IGNORECASE
)
_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)
_META_SNIFF_BYTES = 4096
_BASE64_WHITESPACE = b" \t\r\n\x0b\x0c"


@dataclass(frozen=True, slots=True)
class Hashes:
    md5: str
    sha1: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class TextResult:
    text: str
    charset_used: str
    fallback: bool


def hash_bytes(data: bytes) -> Hashes:
    """All three digests in one pass over the same bytes (SPEC §15).

    Different receiving systems use different ones, and the pass is the same work for three
    as for one. The bytes are not retained by this function: an attachment over the size
    limit is hashed and dropped, so the consumer can still identify a file we do not serve.
    """
    return Hashes(
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )


def decode_transfer(payload: bytes, encoding: str | None) -> tuple[bytes | None, bool]:
    """Decode a transfer encoding. Returns `(bytes, damaged)`; `(None, True)` is unreadable.

    The standard library is nearly silent about damage here (F8): a truncated
    quoted-printable sequence produces no defect at all, and broken base64 produces bytes
    plus a defect that also fires for benign reasons. So `attachment_unreadable` is defined
    by this decoder: the byte stream could not be reconstructed faithfully.
    """
    name = (encoding or "7bit").strip().lower()
    if name in ("7bit", "8bit", "binary", ""):
        return payload, False
    if name == "base64":
        # translate() strips at C speed; the obvious per-byte comprehension is ~50x slower
        # and turns a 25 MB attachment into seconds of the dissection budget for nothing.
        stripped = payload.translate(None, _BASE64_WHITESPACE)
        if not stripped:
            return b"", bool(payload.strip())
        if len(stripped.rstrip(b"=")) % 4 == 1:
            # No amount of padding makes this decodable: the material is damaged.
            return None, True
        try:
            return b64decode(stripped, validate=True), False
        except (binascii.Error, ValueError):
            try:
                # Best effort: drop what cannot belong to the alphabet and say it was damaged.
                return b64decode(stripped + b"===", validate=False), True
            except (binascii.Error, ValueError):
                return None, True
    if name == "quoted-printable":
        try:
            return quopri.decodestring(payload), False
        except ValueError:
            return None, True
    if name in ("uuencode", "x-uuencode", "uue", "x-uue"):
        return payload, True  # Rare and not part of MIME proper; kept, marked as damaged.
    # An encoding we do not know is not a reason to lose the part.
    return payload, True


def decode_text(data: bytes, declared: str | None, *, is_html: bool = False) -> TextResult:
    """The fixed ladder of SPEC §7.2. Never raises; the last rung cannot fail.

    `fallback` says the text is not what the message claimed it was: either a declaration
    existed and a different codec was used, or characters had to be replaced. No declaration
    and a clean decode is not a fallback — flagging it would make the flag meaningless on
    the majority of mail, which declares nothing.
    """
    normalised = (declared or "").strip().strip('"').lower() or None
    declared_canonical = _canonical(normalised)

    for bom, codec in _BOMS:
        if data.startswith(bom):
            name = codecs.lookup(codec).name
            try:
                return TextResult(data.decode(codec), name, declared_canonical not in (None, name))
            except (UnicodeDecodeError, ValueError):
                return TextResult(data.decode(codec, errors="replace"), name, True)

    candidates: list[str] = []
    if normalised:
        candidates.append(normalised)
    if is_html:
        meta = _META_CHARSET.search(data[:_META_SNIFF_BYTES])
        if meta:
            candidates.append(meta.group(1).decode("ascii", "replace").lower())
    candidates += ["utf-8", "cp1252"]

    for candidate in candidates:
        try:
            codec_info = codecs.lookup(candidate)
        except (LookupError, ValueError):
            # A name the lookup cannot even read - a lone surrogate from an 8-bit byte, a NUL
            # - raises ValueError rather than LookupError, and is just as unresolvable (F17).
            continue
        try:
            text = data.decode(codec_info.name)
        except (UnicodeDecodeError, ValueError):
            continue
        used = codec_info.name
        return TextResult(text, used, declared_canonical not in (None, used))

    # latin-1 maps every byte, so the ladder always terminates - but reaching it means every
    # candidate failed, which is a fallback whether or not anything was declared.
    return TextResult(data.decode("latin-1"), "iso8859-1", True)


def _canonical(name: str | None) -> str | None:
    if not name:
        return None
    try:
        return codecs.lookup(name).name
    except (LookupError, ValueError):
        return name
