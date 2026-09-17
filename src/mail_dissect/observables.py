"""Indicator candidates: the grammars, the registries, and the order (SPEC §11).

The consumer gets **candidates, not verdicts**. Nothing is filtered by value — not private
addresses, not sentence noise — because whether something is interesting depends entirely on
who is asking, and that is the one question this service refuses to answer.

Recognition is grammar crossed with a registry. Grammar says "this has the shape of a
domain", the registry says "this final label exists in the world". Neither is enough alone:
grammar would call `wersja.1.2` a domain, and a registry alone could not tell an address from
a sentence.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .models import ObservableSubtype, ObservableType, SourceKind
from .registries import MAX_HOST_LENGTH, Registries
from .urls import UrlParts, canonical_host, split

# SPEC §11.3: the closed defang table. Matched in its WRITTEN form, never by rewriting the
# text first - rewriting would destroy the offsets that first-occurrence ordering depends on.
_DEFANG_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[:]", ":"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[@]", "@"),
)
_DEFANG_SCHEMES: tuple[tuple[str, str], ...] = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
)
_DEFANG_MARKER = re.compile(
    r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]|\[at\]|\(at\)|\[@\]|h[xX]{2}ps?|f[xX]p",
)

_MARKERS = r"(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]|\[at\]|\(at\)|\[@\])"
_SAFE_CHARS = r"[A-Za-z0-9@:._/-]"
_TOKEN_CHARS = r"[A-Za-z0-9\[\](){}@:._/-]"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST = rf"(?:{_LABEL}\.)+{_LABEL}"
_URL_TAIL = r"[^\s<>\"'\]\),]*"
# Excludes `@` and `/` so the opaque-scheme branch has exactly one way to match:
# `tail [@/] tail` with the same class on both sides backtracks quadratically.
_URL_HEAD = r"[^\s<>\"'\]\),@/]*"
_LOCAL_PART = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"

# The order of these alternatives IS the contract for resolving overlaps (SPEC §11.2):
# leftmost match wins, and at the same position the earlier alternative wins.
_MASTER = re.compile(
    "|".join(
        (
            # A URI with a scheme. An opaque scheme must carry an `@` or a `/`, which is
            #    what separates `mailto:a@example.com` from the `Note:this` in a sentence -
            #    a structural test, not a list of schemes we happen to like.
            rf"(?P<url_scheme>\b[A-Za-z][A-Za-z0-9+.-]*:(?://{_URL_TAIL}|{_URL_HEAD}[@/]{_URL_TAIL}))",
            # 3. An address.
            rf"(?P<email>\b{_LOCAL_PART}@{_HOST})",
            # 4. A URL without a scheme: shorteners and `www.` are everyday mail content.
            rf"(?P<url_bare>\b(?:www\.{_HOST}{_URL_TAIL}|{_HOST}/{_URL_TAIL}))",
            # 5/6. Loose shapes, validated by a real address parser rather than by the regex.
            r"(?P<ipv6>(?<![:.\w])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:.]{0,45})",
            r"(?P<ipv4>(?<![\w.-])\d{1,3}(?:\.\d{1,3}){3}(?![\w.-]))",
            # 7. A written-down digest.
            r"(?P<hash>\b[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?(?:[0-9a-fA-F]{24})?(?:[0-9a-fA-F]{64})?\b)",
            # 8. A token the registries decide about: a domain, a filename, both, or neither.
            rf"(?P<token>\b{_LABEL}(?:\.{_LABEL})+)",
        )
    )
)
# Defanged forms are found by locating the MARKER and expanding around it, never by a
# pattern that walks forward looking for one. Any "run of characters, then a required
# marker" construction costs a walk back over the run at every position where there is no
# marker - quadratic on the long unbroken runs mail is full of, and measurably so: 154
# seconds for 200 kB before this was restructured.
_MARKER_SEARCH = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]|\[at\]|\(at\)|\[@\]")
_DEFANG_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[](){}@:._/-"
)
_MAX_DEFANG_TOKEN = 2048

_TRAILING_PUNCTUATION = ".,;:!?\"'"
_CLOSERS = {")": "(", "]": "[", "}": "{"}
_HASH_SUBTYPES: dict[int, ObservableSubtype] = {
    32: "md5",
    40: "sha1",
    64: "sha256",
    128: "sha512",
}


@dataclass(frozen=True, slots=True)
class Source:
    kind: SourceKind
    header_name: str | None = None
    header_index: int | None = None
    part_index: int | None = None


@dataclass(slots=True)
class Candidate:
    value: str
    value_raw: str
    type: ObservableType
    subtype: ObservableSubtype | None = None
    defanged: bool = False
    ambiguous: bool = False
    occurrences: int = 0
    sources: list[Source] = field(default_factory=list)


class Collector:
    """Append-only, so the deterministic core of the list never moves `[D9]`.

    Candidates from an optional tool can only ever extend the tail: a consumer comparing two
    dissections of the same message, one with the text extractor and one without, sees the
    same entries in the same positions and a longer list.
    """

    __slots__ = ("_order", "_registries", "_seen")

    def __init__(self, registries: Registries) -> None:
        self._registries = registries
        self._seen: dict[tuple[str, str], Candidate] = {}
        self._order: list[Candidate] = []

    def feed_text(self, text: str, source: Source) -> None:
        """Scan a blob; overlapping matches are resolved once, in document order.

        Leftmost wins, and at the same position the defanged reading wins — `hxxp:` is a
        syntactically valid scheme, so the URL grammar would otherwise swallow
        `hxxp://zly[.]host` and hand back a broken address.
        """
        for kind, raw in _scan(text):
            trimmed = _trim(raw)
            if trimmed:
                self._classify(kind, trimmed, source)

    def feed_url(self, href: str, source: Source) -> None:
        """An address taken from an anchor or a resource, which needs no grammar to find."""
        if not href:
            return
        self._emit(href, href, "url", source)
        self._fan_out_url(href, href, source, defanged=False)

    def finish(self) -> list[Candidate]:
        return self._order

    # -- classification ----------------------------------------------------------------
    def _classify(self, kind: str, raw: str, source: Source) -> None:
        if kind == "defanged":
            self._classify_defanged(raw, source)
        elif kind in ("url_scheme", "url_bare"):
            value = _canonical_url(raw)
            self._emit(value, raw, "url", source)
            self._fan_out_url(value, raw, source, defanged=False)
        elif kind == "email":
            self._emit_email(raw, raw, source, defanged=False)
        elif kind == "ipv4" or kind == "ipv6":
            address = _valid_ip(raw)
            if address is not None:
                self._emit(address[0], raw, "ip", source, subtype=address[1])
        elif kind == "hash":
            subtype = _HASH_SUBTYPES.get(len(raw))
            if subtype is not None:
                self._emit(raw.lower(), raw, "hash", source, subtype=subtype)
        elif kind == "token":
            self._classify_token(raw, raw, source, defanged=False)

    def _classify_defanged(self, raw: str, source: Source) -> None:
        """Re-arm, then re-classify. `defanged` says the difference comes from re-arming."""
        rearmed = _rearm(raw)
        if rearmed == raw:
            return
        match = _MASTER.fullmatch(rearmed)
        if match is None or match.lastgroup in (None, "defanged"):
            return
        kind = match.lastgroup
        if kind in ("url_scheme", "url_bare"):
            value = _canonical_url(rearmed)
            self._emit(value, raw, "url", source, defanged=True)
            self._fan_out_url(value, raw, source, defanged=True)
        elif kind == "email":
            self._emit_email(rearmed, raw, source, defanged=True)
        elif kind == "token":
            self._classify_token(rearmed, raw, source, defanged=True)
        elif kind in ("ipv4", "ipv6"):
            address = _valid_ip(rearmed)
            if address is not None:
                self._emit(address[0], raw, "ip", source, subtype=address[1], defanged=True)

    def _classify_token(self, token: str, raw: str, source: Source, *, defanged: bool) -> None:
        """The registry gate, and the one collision that sets `ambiguous` (SPEC §11.3)."""
        if len(token) > MAX_HOST_LENGTH:
            # Longer than a host may be (RFC 1035) and longer than any filename we would
            # serve: an unbroken run of `a.b.a.b…` is one token to the grammar, and handing
            # it to the registry would cost more than reading the message did.
            return
        host, _ = canonical_host(token)
        is_domain = self._registries.public_suffix(host) is not None
        extension = token.rsplit(".", 1)[-1].lower()
        is_filename = self._registries.is_known_extension(extension)
        both = is_domain and is_filename
        if is_domain:
            self._emit(host, raw, "domain", source, defanged=defanged, ambiguous=both)
        if is_filename:
            self._emit(token, raw, "filename", source, defanged=defanged, ambiguous=both)

    def _emit_email(self, address: str, raw: str, source: Source, *, defanged: bool) -> None:
        local, _, domain = address.rpartition("@")
        host, _ = canonical_host(domain)
        self._emit(f"{local}@{host}", raw, "email", source, defanged=defanged)
        # Decompose, do not select: a consumer after domains should not have to parse.
        self._emit_host(host, raw, source, defanged=defanged)

    def _fan_out_url(self, url: str, raw: str, source: Source, *, defanged: bool) -> None:
        parts = _parse_url(url)
        if parts.host:
            self._emit_host(parts.host, raw, source, defanged=defanged)
        elif parts.scheme == "mailto" and parts.path and "@" in parts.path:
            self._emit_email(parts.path, raw, source, defanged=defanged)

    def _emit_host(self, host: str, raw: str, source: Source, *, defanged: bool) -> None:
        address = _valid_ip(host)
        if address is not None:
            self._emit(address[0], raw, "ip", source, subtype=address[1], defanged=defanged)
        elif self._registries.public_suffix(host) is not None:
            self._emit(host, raw, "domain", source, defanged=defanged)

    def _emit(
        self,
        value: str,
        raw: str,
        type_: ObservableType,
        source: Source,
        *,
        subtype: ObservableSubtype | None = None,
        defanged: bool = False,
        ambiguous: bool = False,
    ) -> None:
        """Deduplicate by `(value, type)`; count every occurrence, list distinct places."""
        key = (value, type_)
        candidate = self._seen.get(key)
        if candidate is None:
            candidate = Candidate(
                value=value,
                value_raw=raw,
                type=type_,
                subtype=subtype,
                defanged=defanged,
                ambiguous=ambiguous,
            )
            self._seen[key] = candidate
            self._order.append(candidate)
        candidate.occurrences += 1
        # [D14]: `sources` lists distinct PLACES; five hits in one body is one source.
        if source not in candidate.sources:
            candidate.sources.append(source)


def _scan(text: str) -> list[tuple[str, str]]:
    """Every candidate span in document order, with overlaps resolved."""
    found: list[tuple[int, int, int, str, str]] = []
    for marker in _MARKER_SEARCH.finditer(text):
        start, end = _expand(text, marker.start(), marker.end())
        # 0 = the defanged reading, which wins a tie at the same position.
        found.append((start, 0, end, "defanged", text[start:end]))
    for match in _MASTER.finditer(text):
        if match.lastgroup is not None:
            found.append((match.start(), 1, match.end(), match.lastgroup, match.group()))

    found.sort(key=lambda item: (item[0], item[1]))
    taken: list[tuple[str, str]] = []
    consumed_to = -1
    for start, _, end, kind, raw in found:
        if start < consumed_to:
            continue
        taken.append((kind, raw))
        consumed_to = end
    return taken


def _expand(text: str, start: int, end: int) -> tuple[int, int]:
    """Grow a marker outwards to the token that contains it."""
    left = start
    while left > 0 and text[left - 1] in _DEFANG_TOKEN_CHARS and start - left < _MAX_DEFANG_TOKEN:
        left -= 1
    right = end
    length = len(text)
    while right < length and text[right] in _DEFANG_TOKEN_CHARS and right - end < _MAX_DEFANG_TOKEN:
        right += 1
    return left, right


def _trim(raw: str) -> str:
    """Strip trailing punctuation a sentence leaves behind, parenthesis-balance aware."""
    value = raw
    while value:
        last = value[-1]
        if last in _TRAILING_PUNCTUATION:
            value = value[:-1]
            continue
        if last in _CLOSERS and value.count(_CLOSERS[last]) < value.count(last):
            value = value[:-1]
            continue
        break
    return value


def _rearm(raw: str) -> str:
    value = raw
    for written, real in _DEFANG_REPLACEMENTS:
        value = value.replace(written, real)
    lowered = value.lower()
    for written, real in _DEFANG_SCHEMES:
        if lowered.startswith(written):
            value = real + value[len(written) :]
            break
    return value


def _parse_url(url: str) -> UrlParts:
    """Split an address, including one written without a scheme.

    `urlsplit` reads `bit.ly/xyz` as a path, not as a host - so a schemeless address is
    re-read with an authority marker in front of it. Shorteners and `www.` forms are
    everyday mail content, and losing them would be a decision about what matters.
    """
    parts = split(url)
    if parts.scheme is None and parts.host is None:
        parts = split(f"//{url}")
    return parts


def _canonical_url(url: str) -> str:
    """Host lowercased and in punycode; path and query UNTOUCHED (SPEC §11.3).

    Rebuilt from the parts rather than by string surgery on the original: the host appears in
    the text in whatever case the sender chose, so cutting the string at it is a trap.
    """
    parts = _parse_url(url)
    if not parts.host:
        return url
    authority = f"{parts.host}:{parts.port}" if parts.port else parts.host
    if parts.userinfo:
        authority = f"{parts.userinfo}@{authority}"
    rebuilt = f"{parts.scheme}://{authority}" if parts.scheme else authority
    rebuilt += parts.path or ""
    if parts.query:
        rebuilt += f"?{parts.query}"
    if parts.fragment:
        rebuilt += f"#{parts.fragment}"
    return rebuilt


def _valid_ip(text: str) -> tuple[str, ObservableSubtype] | None:
    """Shape is matched loosely and validated here: `10:30:45` is not an address."""
    candidate = text.strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(address), ("ipv4" if address.version == 4 else "ipv6")


def has_defang_marker(text: str) -> bool:
    return _DEFANG_MARKER.search(text) is not None
