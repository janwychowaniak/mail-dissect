"""Header reading: every header, in order, unfolded and decoded (SPEC §7).

RFC 2047 goes through `HeaderRegistry`, never `make_header(decode_header(...))`, which raises
on input a hostile sender fully controls (F7). The registry is remapped first, because two of
the address headers the contract names are not address types in the standard library (F6),
and it is given unfolded values, because unfolding is the policy's job and not its own (F18).
"""

from __future__ import annotations

import codecs
import email.message
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from email.headerregistry import Address as StdlibAddress
from email.headerregistry import AddressHeader, HeaderRegistry, UniqueAddressHeader
from email.message import Message
from email.parser import BytesHeaderParser
from email.policy import Compat32
from email.utils import collapse_rfc2231_value, decode_params, unquote

from .models import substituted


class _Compat32Text(Compat32):
    """`compat32` that hands every header value out as the unfolded string it holds.

    Stock `compat32` wraps a value holding 8-bit bytes in an `email.header.Header` (F17), and
    nothing here expects one: it reached `.strip()` and a regex, and one byte above 0x7F in any
    header of a message was a 500. As a string the bytes stay lone surrogates, which is the
    shape `[D20]` scrubs at the response boundary and reports as `encoding_fallback`.

    It also hands the value out exactly as it was stored, line breaks included, and nothing
    here expects those either (F18): the header registry refuses an address with one in it,
    keeps it inside an unstructured value, and drops the parameters that follow it. Where a
    writer broke a line is not part of the value (RFC 5322 §2.2.3), so the break is removed
    here, once, for everything that reads a header — the message's, a part's, a nested
    message's `[D24]`. The white space after the break stays.

    Only fetching changes; parsing is compat32's own, so `[D11]` holds.
    """

    def header_fetch_parse(self, name: str, value: str) -> str:
        # A CR or LF inside a stored value is a fold and nothing else: the header ended at the
        # first line that did not start with white space. `policy.default` removes the same
        # characters, as `\n|\r\n?`; two replacements cost a fetch next to nothing, which
        # matters because the parser fetches several headers for every part (F3).
        return value.replace("\r", "").replace("\n", "")


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


# An RFC 2047 encoded-word; its charset may carry an RFC 2231 language suffix (`utf-8*en`).
_ENCODED_WORD = re.compile(r"=\?([^?*\s]+)(?:\*[^?\s]*)?\?[QqBb]\?[^?\s]*\?=")


def header_map(raw: bytes) -> tuple[dict[str, list[str]], bool]:
    """Every header, names lowercased, values in order of appearance (SPEC §7).

    No selection: `headers` returns all of them, because choosing which matter is the
    consumer's business. The second value says whether reading any of them fell back, which
    is `encoding_fallback` (SPEC §5.1).
    """
    message = BytesHeaderParser(policy=COMPAT32_TEXT).parsebytes(raw)
    result: dict[str, list[str]] = {}
    fell_back = False
    for name, value in message.items():
        decoded, this_fell_back = _read(name, value)
        fell_back = fell_back or this_fell_back
        result.setdefault(name.lower(), []).append(decoded)
    return result, fell_back


def _read(name: str, value: str) -> tuple[str, bool]:
    """One header value decoded, and whether that fell back (SPEC §5.1).

    The registry takes neither kind of fallback aloud: an encoded-word in a charset nobody can
    look up comes back undecoded, and bytes that do not decode come back as U+FFFD - an 8-bit
    byte and a broken encoded-word alike - and neither leaves a defect (F7, F17).
    """
    decoded = decode_value(name, value)
    unknown = any(not _known_charset(m.group(1)) for m in _ENCODED_WORD.finditer(value))
    return decoded, unknown or substituted(value, decoded)


def _known_charset(name: str | None) -> bool:
    if not name:
        return True  # Nothing was declared, so nothing was refused.
    try:
        codecs.lookup(name)
    except (LookupError, ValueError):
        return False
    return True


def filename_of(part: Message) -> tuple[str | None, bool]:
    """The part's name as the message wrote it — not yet sanitised — and whether reading it
    fell back (SPEC §6.4, §5.1, `[D27]`).

    `filename` in `Content-Disposition` is the name, and `name` in `Content-Type` only where
    the first is not written at all. Within one header the RFC 2231 form, in any of its shapes,
    wins over the plain one wherever it stands — unless its declared charset is not taken, and
    then the plain one is read and the fallback reported.

    The plain form is read as unstructured text: the white space between two adjacent
    encoded-words goes (RFC 2047 §6.2) and everything else stays as written. An encoded-word
    inside a quoted string is non-standard but common (F4). The form with a charset is decoded
    in that charset and read no further. Path components stay: that is the service's job
    when it serves the name (SPEC §13.3).
    """
    for header, param in (("content-disposition", "filename"), ("content-type", "name")):
        plain, extended = _written_name(part, header, param)
        if isinstance(extended, tuple):
            # A charset was declared. The standard library reads one it cannot look up as some
            # other charset, and bytes that do not decode as U+FFFD, and says nothing about
            # either, so whether the declaration holds is asked here.
            if _decodes(extended[0], extended[2]):
                return _edges(collapse_rfc2231_value(extended)), False
            if plain is None:
                return _edges(collapse_rfc2231_value(extended)), True
            return _plain_name(plain)[0], True
        if extended is not None:
            return _plain_name(extended)
        if plain is not None:
            return _plain_name(plain)
    return None, False


# A name the header registry has no class for, so a value read under it is unstructured text:
# the grammar of `Subject`. The grammar of the header the name came from is not the one: given
# the bare name as a `Content-Disposition` value, its parser fails at the first `=`, recovers
# through the grammar of a display name, and rewrites a `;` and what follows it as a parameter
# of its own — and whether it drops the white space between two encoded-words depends on the
# patch release of Python (F21).
_UNSTRUCTURED = "x-mail-dissect-filename"

# How `Message.get_params` splits a header into its parameters, quotes and all. It has no
# public name; the names it keeps are what `_written_name` needs and `get_params` throws away.
_split_parameters: Callable[[str], list[str]]
_split_parameters = email.message._parseparam  # type: ignore[attr-defined]


def _written_name(
    part: Message, header: str, param: str
) -> tuple[str | None, str | tuple[str | None, str | None, str] | None]:
    """The plain form of the parameter and its RFC 2231 form, each as written, or `None`.

    The parameters are split as `Message.get_params` splits them, quotes and all, but the
    names are kept: once the standard library has joined the RFC 2231 segments, nothing tells a
    continued value without a charset from a plain one, and the rule needs to know which was
    written (`[D27]`). The joining itself is the standard library's.
    """
    value = part.get(header)
    if value is None:
        return None, None
    plain: str | None = None
    segments: list[tuple[str, str]] = []
    for item in _split_parameters(str(value))[1:]:
        name, _, written = item.partition("=")
        name, written = name.strip(), written.strip()
        if name == param:
            if plain is None:  # A second plain one is ignored, as `get_param` ignores it.
                plain = unquote(written)
        elif re.fullmatch(rf"{re.escape(param)}\*(?:[0-9]+\*?)?", name):
            segments.append((name, written))
    if not segments:
        return plain, None
    joined = decode_params([("", ""), *segments])[1][1]
    if isinstance(joined, tuple):
        return plain, (joined[0], joined[1], unquote(joined[2]))
    return plain, unquote(joined)


def _plain_name(written: str) -> tuple[str | None, bool]:
    """A name written without a charset: its encoded-words decoded, and whether that fell back."""
    if "=?" not in written:
        return _edges(written), False
    decoded, fell_back = _read(_UNSTRUCTURED, written)
    return _edges(decoded), fell_back


def _edges(name: str) -> str | None:
    """White space at either end is not part of a name; a period there is (`[D27]`)."""
    return name.strip() or None


def _decodes(charset: str | None, text: str) -> bool:
    """Does an RFC 2231 value decode, strictly, in the charset it declares?

    The bytes `email.utils.collapse_rfc2231_value` decodes, without its two silences: it
    decodes with `replace`, and it falls back on a charset it cannot find.
    """
    if not charset:
        return True
    try:
        bytes(text, "raw-unicode-escape").decode(charset)
    except (LookupError, ValueError):
        return False
    return True


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
            if not entry.domain and entry.username:
                entry = _written_inside(lowered, entry.username) or entry
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


def _written_inside(name: str, local_part: str) -> StdlibAddress | None:
    """The address a local part turns out to be, when it is exactly one `[D25]`.

    `"Bob Example <bob@example.net>"` is, by the grammar, a quoted local part with no domain,
    and the entry the parser returns for it is not an address anybody can use. The local part
    is read once more, by the same parser, and taken only when that gives one mailbox with a
    domain and no defect - the defect being what tells a clean reading from a mailbox found
    in front of something the parser gave up on. Read once: the result is never read again.
    """
    try:
        header = _registry(name, local_part)
    except Exception:
        return None
    found: tuple[StdlibAddress, ...] = getattr(header, "addresses", ())
    if len(found) != 1 or not found[0].domain or header.defects:
        return None
    return found[0]


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
