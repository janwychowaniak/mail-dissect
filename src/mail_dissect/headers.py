"""Header reading: every header, in order, decoded (SPEC §7).

RFC 2047 goes through `HeaderRegistry`, never `make_header(decode_header(...))`, which raises
on input a hostile sender fully controls (F7). The registry is remapped first, because two of
the address headers the contract names are not address types in the standard library (F6).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email.headerregistry import AddressHeader, HeaderRegistry, UniqueAddressHeader
from email.message import Message
from email.parser import BytesHeaderParser
from email.policy import Compat32


class _Compat32Text(Compat32):
    """`compat32` that hands every header value out as the string it was parsed into.

    Stock `compat32` wraps a value holding 8-bit bytes in an `email.header.Header` (F17), and
    nothing here expects one: it reached `.strip()` and a regex, and one byte above 0x7F in any
    header of a message was a 500. As a string the bytes stay lone surrogates, which is the
    shape `[D20]` scrubs at the response boundary and reports as `encoding_fallback`. Only
    fetching changes; parsing is compat32's own, so `[D11]` holds.
    """

    def header_fetch_parse(self, name: str, value: str) -> str:
        return value


COMPAT32_TEXT = _Compat32Text()

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


def header_map(raw: bytes) -> tuple[dict[str, list[str]], bool]:
    """Every header, names lowercased, values in order of appearance (SPEC §7).

    No selection: `headers` returns all of them, because choosing which matter is the
    consumer's business. The second value says whether decoding substituted anything: the
    registry puts U+FFFD where bytes do not decode, an 8-bit byte or a broken encoded-word
    alike, and says nothing (F7, F17), so the substitution is counted here and reported as
    `encoding_fallback` (SPEC §7.2).
    """
    message = BytesHeaderParser(policy=COMPAT32_TEXT).parsebytes(raw)
    result: dict[str, list[str]] = {}
    substituted = False
    for name, value in message.items():
        decoded = decode_value(name, value)
        substituted = substituted or _substituted(value, decoded)
        result.setdefault(name.lower(), []).append(decoded)
    return result, substituted


def _substituted(value: str, decoded: str) -> bool:
    """Whether `decoded` has a U+FFFD that the sender did not write.

    A U+FFFD the sender did write arrives either as the character itself or, in a raw 8-bit
    header, as its three UTF-8 bytes escaped to surrogates; both are counted as written.
    """
    written = value.count("\ufffd") + value.count("\udcef\udcbf\udcbd")
    return decoded.count("\ufffd") > written


def filename_of(part: Message) -> str | None:
    """The attachment's name as the message wrote it — not yet sanitised.

    `policy.default` is used only for this one value: it is the only policy that decodes an
    RFC 2047 encoded-word inside a filename, which is non-standard but common (F4). Neither
    policy strips path components, so that stays the service's job (SPEC §13.3).
    """
    name = part.get_filename()
    if not name:
        return None
    if "=?" in name:
        name = decode_value("content-disposition", name)
    return name or None


@dataclass(frozen=True, slots=True)
class Address:
    display_name: str | None
    address: str | None
    local_part: str | None
    domain: str | None


@dataclass(frozen=True, slots=True)
class Hop:
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    with_: str | None = None
    id: str | None = None
    for_: str | None = None
    timestamp: str | None = None


@dataclass(frozen=True, slots=True)
class AuthResult:
    method: str
    result: str
    params: dict[str, str]


# Candidates only: hostnames are full of hex letters, so `mail.example.com` yields
# "e.c" to any shape-based pattern. Every candidate is validated as a real address.
_IP_CANDIDATE = re.compile(r"[0-9a-fA-F:.]{3,45}")
_RECEIVED_TOKEN = re.compile(
    r"\b(from|by|with|id|for|via)\s+([^\s;]+(?:\s*\([^)]*\))?)", re.IGNORECASE
)
_AUTH_METHOD = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*([A-Za-z0-9_-]+)")
_AUTH_PARAM = re.compile(r"([A-Za-z0-9_.-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)")


def addresses_of(raw: bytes) -> dict[str, list[Address]]:
    """Decompose EVERY address header present, in full (SPEC §7).

    Not a chosen three: decomposing one costs the same as decomposing all of them, and
    choosing would be a decision about which headers matter.
    """
    message = BytesHeaderParser(policy=COMPAT32_TEXT).parsebytes(raw)
    result: dict[str, list[Address]] = {}
    for name, value in message.items():
        lowered = name.lower()
        if lowered not in ADDRESS_HEADERS:
            continue
        parsed: list[Address] = []
        try:
            header = _registry(lowered, value)
            entries = getattr(header, "addresses", ())
        except Exception:
            entries = ()
        for entry in entries:
            spec = str(entry.addr_spec) if entry.addr_spec else None
            parsed.append(
                Address(
                    display_name=str(entry.display_name) or None,
                    address=spec,
                    local_part=str(entry.username) or None,
                    domain=str(entry.domain) or None,
                )
            )
        if not parsed and value.strip():
            # A header we cannot decompose is still reported, with nulls where the parts
            # would be: the raw value stays in `headers` either way.
            parsed.append(Address(None, None, None, None))
        result.setdefault(lowered, []).extend(parsed)
    return result


def parse_received(value: str) -> Hop:
    """One `Received` hop. Missing fields are null — the header is often incomplete (§7)."""
    body, _, timestamp = value.rpartition(";")
    if not body:
        body, timestamp = value, ""
    fields: dict[str, str] = {}
    for match in _RECEIVED_TOKEN.finditer(body):
        key = match.group(1).lower()
        if key not in fields:
            fields[key] = match.group(2).strip()
    from_value = fields.get("from")
    from_host, from_ip = _split_host_and_ip(from_value)
    return Hop(
        from_host=from_host,
        from_ip=from_ip,
        by_host=_bare(fields.get("by")),
        with_=_bare(fields.get("with")),
        id=_bare(fields.get("id")),
        for_=_bare(fields.get("for")),
        timestamp=timestamp.strip() or None,
    )


def _bare(value: str | None) -> str | None:
    if not value:
        return None
    return value.split("(")[0].strip().strip("<>") or None


def _split_host_and_ip(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    host = _bare(value)
    ip = None
    if "(" in value:
        ip = _first_ip(value[value.index("(") :])
    if host and host.startswith("[") and host.endswith("]"):
        ip, host = host[1:-1], None
    return host, ip


def _first_ip(text: str) -> str | None:
    """The first token in `text` that really is an IP address."""
    for match in _IP_CANDIDATE.finditer(text):
        candidate = match.group(0).strip(".")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return None


def parse_auth_results(value: str) -> list[AuthResult]:
    """EVERY method present, with the result as written and its parameters (SPEC §7).

    Not the familiar three: a consumer who needs `arc` tomorrow should not have to wait for
    a contract change.
    """
    results: list[AuthResult] = []
    for chunk in value.split(";")[1:]:
        method_match = _AUTH_METHOD.match(chunk)
        if not method_match:
            continue
        method, result = method_match.group(1).lower(), method_match.group(2).lower()
        params: dict[str, str] = {}
        for param in _AUTH_PARAM.finditer(chunk[method_match.end() :]):
            params[param.group(1).lower()] = param.group(2).strip('"')
        results.append(AuthResult(method=method, result=result, params=params))
    return results
