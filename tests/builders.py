"""Synthetic messages, built as exact bytes.

Test material is synthetic only (SPEC §18) — never a third-party corpus. These builders
produce bytes directly rather than going through `email.generator`, because the generator
normalises exactly the malformations the service exists to survive, and a fixture that is
silently repaired proves nothing.
"""

from __future__ import annotations

import base64
import quopri

CRLF = b"\r\n"


def _headers(items: dict[str, str] | list[tuple[str, str]]) -> bytes:
    pairs = items.items() if isinstance(items, dict) else items
    return CRLF.join(f"{name}: {value}".encode() for name, value in pairs)


def message(
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    *,
    body: bytes = b"",
    raw_headers: bytes | None = None,
) -> bytes:
    """A message: headers, a blank line, body. `raw_headers` writes the block verbatim."""
    block = raw_headers if raw_headers is not None else _headers(headers or {})
    return block + CRLF + CRLF + body


def part(
    content_type: str,
    payload: bytes,
    *,
    encoding: str | None = None,
    disposition: str | None = None,
    filename: str | None = None,
    content_id: str | None = None,
    charset: str | None = None,
    extra: dict[str, str] | None = None,
) -> bytes:
    """One MIME part: its headers, a blank line, and the (possibly encoded) payload."""
    type_value = content_type
    if charset:
        type_value = f"{content_type}; charset={charset}"
    items: list[tuple[str, str]] = [("Content-Type", type_value)]
    if encoding:
        items.append(("Content-Transfer-Encoding", encoding))
    if disposition or filename:
        value = disposition or "attachment"
        if filename:
            value = f'{value}; filename="{filename}"'
        items.append(("Content-Disposition", value))
    if content_id:
        items.append(("Content-ID", content_id))
    for name, value in (extra or {}).items():
        items.append((name, value))

    if encoding == "base64":
        encoded = CRLF.join(
            base64.b64encode(payload)[i : i + 76]
            for i in range(0, len(base64.b64encode(payload)), 76)
        )
    elif encoding == "quoted-printable":
        encoded = quopri.encodestring(payload)
    else:
        encoded = payload
    return _headers(items) + CRLF + CRLF + encoded


def multipart(
    subtype: str,
    *parts: bytes,
    boundary: str = "BB",
    headers: dict[str, str] | None = None,
    close: bool = True,
) -> bytes:
    """A multipart container. `close=False` omits the closing delimiter, as broken mail does."""
    items = dict(headers or {})
    items["Content-Type"] = f'multipart/{subtype}; boundary="{boundary}"'
    marker = f"--{boundary}".encode()
    chunks = [_headers(items) + CRLF + CRLF]
    for piece in parts:
        chunks.append(marker + CRLF + piece + CRLF)
    if close:
        chunks.append(marker + b"--" + CRLF)
    return b"".join(chunks)


def nested(inner: bytes, *, encoding: str | None = None) -> bytes:
    """A `message/rfc822` part carrying `inner`, optionally transport-encoded (F2)."""
    return part("message/rfc822", inner, encoding=encoding)


def simple_text(text: str = "hello world") -> bytes:
    return message(
        {"From": "sender@example.com", "To": "rcpt@example.com", "Subject": "hello"},
        body=text.encode(),
    )
