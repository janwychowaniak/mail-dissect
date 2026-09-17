"""Reading the message off the request, byte-faithfully, through either channel (SPEC §4).

The framework's own form handling cannot be used here: a non-file part is capped at 1 MB and
text-decoded (F11), which would make the two channels disagree on the same bytes. So the
multipart body is split here, by hand, and the part is taken exactly as it arrived.
"""

from __future__ import annotations

import re

CRLF = b"\r\n"
_BOUNDARY_RE = re.compile(rb'boundary="?([^";,\s]+)"?', re.IGNORECASE)
_NAME_RE = re.compile(rb'name="([^"]*)"|name=([^;\s]+)', re.IGNORECASE)
# RFC 5322 field name: printable ASCII except the colon, and no space — which is what makes
# `From : x` not a header (F1b).
_HEADER_LINE_RE = re.compile(rb"^[\x21-\x39\x3b-\x7e]+:")

FIELD_NAME = b"eml"


def boundary_of(content_type: str) -> bytes | None:
    match = _BOUNDARY_RE.search(content_type.encode("latin-1", "replace"))
    return match.group(1) if match else None


def extract_form_field(body: bytes, boundary: bytes, field: bytes = FIELD_NAME) -> bytes | None:
    """Return one multipart field's bytes exactly as they arrived, or None if absent.

    Deliberately minimal: we need one named part out of a form we produced the contract for,
    not a general form parser. Everything else about the form is ignored.
    """
    delimiter = b"--" + boundary
    chunks = body.split(delimiter)
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):  # closing delimiter
            break
        block = chunk[2:] if chunk.startswith(CRLF) else chunk.lstrip(b"\r\n")
        separator = block.find(CRLF + CRLF)
        if separator == -1:
            continue
        head, payload = block[:separator], block[separator + 4 :]
        name = None
        for line in head.split(CRLF):
            if line[:20].lower().startswith(b"content-disposition:"):
                match = _NAME_RE.search(line)
                if match:
                    name = match.group(1) if match.group(1) is not None else match.group(2)
        if name != field:
            continue
        # The CRLF before the next delimiter belongs to the delimiter, not to the payload.
        return payload[:-2] if payload.endswith(CRLF) else payload.rstrip(b"\n")
    return None


def looks_like_message(raw: bytes) -> bool:
    """The one structural boundary between a message and something else (SPEC §15).

    At least one `Name: value` line before the first empty line. Decided on the raw bytes:
    the standard library swallows a leading `From ` line as an mbox envelope and would report
    a message with no headers at all, without a defect (F1b) — while a genuine mbox export
    legitimately starts with exactly that line.
    """
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    return any(_HEADER_LINE_RE.match(line) for line in lines)
