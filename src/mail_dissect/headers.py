"""Header reading: every header, in order, decoded (SPEC §7).

RFC 2047 goes through `HeaderRegistry`, never `make_header(decode_header(...))`, which raises
on input a hostile sender fully controls (F7). The registry is remapped first, because two of
the address headers the contract names are not address types in the standard library (F6).
"""

from __future__ import annotations

from email.headerregistry import AddressHeader, HeaderRegistry, UniqueAddressHeader
from email.parser import BytesHeaderParser
from email.policy import compat32

ADDRESS_HEADERS = (
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "sender",
    "return-path",
    "resent-from",
    "resent-to",
    "resent-cc",
    "resent-bcc",
    "resent-sender",
    "resent-reply-to",
)

_registry = HeaderRegistry()
# F6: the stdlib registry treats these two as unstructured, so `.addresses` would raise.
# The ignores are a typeshed limitation, not a runtime one: `map_to_type` takes the mixin
# and combines it with BaseHeader itself, which is exactly how the stdlib registers its own
# address headers - verified by the probe behind F6.
_registry.map_to_type("return-path", UniqueAddressHeader)  # type: ignore[arg-type]
_registry.map_to_type("resent-reply-to", AddressHeader)  # type: ignore[arg-type]


def decode_value(name: str, value: str) -> str:
    """Decode one header value (RFC 2047 included). Never raises on hostile input."""
    try:
        return str(_registry(name, value))
    except Exception:
        return value


def header_map(raw: bytes) -> dict[str, list[str]]:
    """Every header, names lowercased, values in order of appearance (SPEC §7).

    No selection: `headers` returns all of them, because choosing which matter is the
    consumer's business.
    """
    message = BytesHeaderParser(policy=compat32).parsebytes(raw)
    result: dict[str, list[str]] = {}
    for name, value in message.items():
        result.setdefault(name.lower(), []).append(decode_value(name, value))
    return result
