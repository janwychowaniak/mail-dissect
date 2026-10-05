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

import bisect
import ipaddress
import re
import string
from collections.abc import Callable, Iterator
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

# The order of these alternatives IS the contract for resolving overlaps (SPEC §11.2): the
# earliest match wins, and at the same position the earlier alternative wins.
#
# 2. A URI with a scheme. An opaque scheme must carry an `@` or a `/`, which is what separates
#    `mailto:a@example.com` from the `Note:this` in a sentence - a structural test, not a list
#    of schemes we happen to like.
_URL_SCHEME = (
    rf"(?P<url_scheme>\b[A-Za-z][A-Za-z0-9+.-]*:(?://{_URL_TAIL}|{_URL_HEAD}[@/]{_URL_TAIL}))"
)
# 3. An address.
_EMAIL = rf"(?P<email>\b{_LOCAL_PART}@{_HOST})"
_OTHERS = "|".join(
    (
        # 4. A URL without a scheme: shorteners and `www.` are everyday mail content.
        rf"(?P<url_bare>\b(?:www\.{_HOST}{_URL_TAIL}|{_HOST}/{_URL_TAIL}))",
        # 5/6. Loose shapes, validated by a real address parser rather than by the regex.
        r"(?P<ipv6>(?<![:.\w])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:.]{0,45})",
        #    [D26]: a label character (`\w`: a letter, a digit or an underscore, in any
        #    script) next to the address rules it out, and so does one on the far side
        #    of a period or a hyphen that touches it - the head of a host name, the tail
        #    of a version. A period or a hyphen with anything else beyond it is
        #    punctuation, on either side.
        r"(?P<ipv4>(?<!\w)(?<!\w[.-])\d{1,3}(?:\.\d{1,3}){3}(?!\w|[.-]\w))",
        # 7. A written-down digest.
        r"(?P<hash>\b[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?(?:[0-9a-fA-F]{24})?(?:[0-9a-fA-F]{64})?\b)",
        # 8. A token the registries decide about: a domain, a filename, both, or neither.
        rf"(?P<token>\b{_LABEL}(?:\.{_LABEL})+)",
    )
)
# The whole alternation, which the defanged path matches a re-armed token against.
_MASTER = re.compile(f"{_URL_SCHEME}|{_EMAIL}|{_OTHERS}")
# The scan finds a URI with a scheme and an address by their anchors (`_anchored`), and the
# rest with this.
_REST = re.compile(_OTHERS)
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

# A text is scanned in chunks, and the deadline is asked between them `[D10]`. A chunk ends
# just before a white-space character, and no candidate contains one, so the chunks give
# exactly what the whole text gives. Every lookaround reads at most two characters beyond a
# match, and white space and the end of a chunk look the same to each of them: neither is a
# label character, a period or a hyphen.
_CHUNK = 65_536
_WHITE_SPACE = re.compile(r"\s")

# [D29]: a run of non-white-space characters longer than this is skipped whole, and the
# response says `truncated`. Its first characters would give readings the run does not
# contain, and a cut would give cut values; the rest of the text reads exactly as before,
# because no candidate contains white space. The lookbehind is what keeps finding a run cheaper
# than reading one: without it, every position inside a run counts to the run's end again
# whenever enough text follows in the chunk, about eight seconds for each run built so.
MAX_RUN_LENGTH = 262_144
_LONG_RUN = re.compile(rf"(?<!\S)\S{{{MAX_RUN_LENGTH + 1},}}")

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

    __slots__ = ("_order", "_registries", "_seen", "_should_stop", "stopped", "truncated")

    def __init__(
        self, registries: Registries, should_stop: Callable[[], bool] | None = None
    ) -> None:
        self._registries = registries
        self._seen: dict[tuple[str, str], Candidate] = {}
        self._order: list[Candidate] = []
        # The deadline, asked before every chunk and every address `[D10]`. Once it has said
        # stop, nothing more is added: the list ends where the scan stopped.
        self._should_stop = should_stop
        self.stopped = False
        # Something the material holds was not read: the scan stopped, or a run was skipped.
        self.truncated = False

    def feed_text(self, text: str, source: Source) -> None:
        """Scan a blob; overlapping matches are resolved once, in document order.

        Leftmost wins, and at the same position the defanged reading wins — `hxxp:` is a
        syntactically valid scheme, so the URL grammar would otherwise swallow
        `hxxp://zly[.]host` and hand back a broken address.
        """
        for chunk in _chunks(text):
            if self._stop():
                return
            for piece in self._without_long_runs(chunk):
                for kind, raw in _scan(piece):
                    trimmed = _trim(raw)
                    if trimmed:
                        self._classify(kind, trimmed, source)

    def feed_url(self, href: str, source: Source) -> None:
        """An address taken from an anchor or a resource, which needs no grammar to find."""
        if not href or self._stop():
            return
        self._emit(href, href, "url", source)
        self._fan_out_url(href, href, source, defanged=False)

    def finish(self) -> list[Candidate]:
        return self._order

    def _stop(self) -> bool:
        if not self.stopped and self._should_stop is not None and self._should_stop():
            self.stopped = True
            self.truncated = True
        return self.stopped

    def _without_long_runs(self, chunk: str) -> list[str]:
        """The chunk with every run longer than `MAX_RUN_LENGTH` left out `[D29]`.

        A run never crosses a chunk, since chunks are cut at white space, and each piece left
        ends and begins with white space, so it reads as it did inside the chunk.
        """
        pieces: list[str] = []
        start = 0
        for run in _LONG_RUN.finditer(chunk):
            self.truncated = True
            pieces.append(chunk[start : run.start()])
            start = run.end()
        if not pieces:
            return [chunk]
        pieces.append(chunk[start:])
        return pieces

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


def _chunks(text: str) -> Iterator[str]:
    """The text in pieces of at least `_CHUNK` characters, each cut before white space."""
    start, length = 0, len(text)
    while length - start > _CHUNK:
        cut = _WHITE_SPACE.search(text, start + _CHUNK)
        if cut is None:
            break
        yield text[start : cut.start()]
        start = cut.start()
    if start < length:
        yield text[start:]


def _scan(text: str) -> list[tuple[str, str]]:
    """Every candidate span in document order, with overlaps resolved."""
    found: list[tuple[int, int, int, str, str]] = []
    for marker in _MARKER_SEARCH.finditer(text):
        start, end = _expand(text, marker.start(), marker.end())
        # 0 = the defanged reading, which wins a tie at the same position.
        found.append((start, 0, end, "defanged", text[start:end]))
    for start, end, kind in _matches(text):
        found.append((start, 1, end, kind, text[start:end]))

    found.sort(key=lambda item: (item[0], item[1]))
    taken: list[tuple[str, str]] = []
    consumed_to = -1
    for start, _, end, kind, raw in found:
        if start < consumed_to:
            continue
        taken.append((kind, raw))
        consumed_to = end
    return taken


def _matches(text: str) -> Iterator[tuple[int, int, str]]:
    """The matches of the whole alternation, in order: what `_MASTER.finditer` would give.

    The earliest match wins, at the same position the earlier alternative, and the next match
    is the earliest at or after the end of the last one. A URI with a scheme comes first and an
    address second, so each wins a tie with what follows it.
    """
    context = _Context(text)
    schemes = _Anchored(context, ":", _scheme_at)
    addresses = _Anchored(context, "@", _address_at)
    rest = _REST.search(text)
    position = 0
    while True:
        best: tuple[int, int, str] | None = None
        scheme = schemes.find(position)
        if scheme is not None:
            best = (*scheme, "url_scheme")
        address = addresses.find(position)
        if address is not None and (best is None or address[0] < best[0]):
            best = (*address, "email")
        if rest is not None and rest.start() < position:
            rest = _REST.search(text, position)
        if rest is not None and (best is None or rest.start() < best[0]):
            best = (rest.start(), rest.end(), rest.lastgroup or "")
        if best is None:
            return
        yield best
        position = best[1]


# A URI with a scheme and an address may start at every word boundary of a run and read to its
# end before they fail, so searching for them is quadratic in the length of a run that nothing
# completes (F22). Both are built the same way: a stretch of characters that ends at one anchor,
# `:` or `@`, and then a part that does not depend on where the stretch began. So each anchor is
# read once, in order: where its stretch begins, which starts in the stretch the grammar admits,
# and where the match after the anchor ends. The earliest match at or after a position is the
# first admitted start of the first anchor that has one - what the search would find, in time
# linear in the text. The stretch is read backwards, as a forward match on the reversed text.
_SCHEME_CHARS = re.compile(r"[A-Za-z0-9+.-]*")
_SCHEME_INNER_START = re.compile(r"[+.-][A-Za-z]")
_LOCAL_REVERSED = re.compile(_LOCAL_PART)  # a dot-atom reads the same backwards
_LOCAL_CHARS = frozenset(string.ascii_letters + string.digits + "!#$%&'*+/=?^_`{|}~-")
_LETTERS = frozenset(string.ascii_letters)
_BOUNDARY = re.compile(r"\b")
_TAIL_STOP = re.compile(r"[\s<>\"'\]\),]")
_HEAD_STOP = re.compile(r"[\s<>\"'\]\),@/]")
_HOST_AT = re.compile(_HOST)


class _Stop:
    """The first position at or after `i` that `pattern` matches, or the end of the text."""

    __slots__ = ("_at", "_from", "_pattern", "_text")

    def __init__(self, text: str, pattern: re.Pattern[str]) -> None:
        self._text = text
        self._pattern = pattern
        self._from, self._at = 1, 0  # nothing known yet

    def __call__(self, i: int) -> int:
        # Nothing matches in [_from, _at), so any `i` in that range has the same answer. The
        # anchors are read in order, so most questions fall in the range of the last answer.
        if self._from <= i <= self._at:
            return self._at
        found = self._pattern.search(self._text, i)
        self._from, self._at = i, found.start() if found else len(self._text)
        return self._at


class _Context:
    """What the readers of both anchors share, made when one of them first needs it."""

    __slots__ = ("_reversed", "head_stop", "tail_stop", "text")

    def __init__(self, text: str) -> None:
        self.text = text
        self._reversed: str | None = None
        self.tail_stop = _Stop(text, _TAIL_STOP)
        self.head_stop = _Stop(text, _HEAD_STOP)

    def stretch(self, pattern: re.Pattern[str], anchor: int) -> int:
        """Where the longest stretch `pattern` matches, ending just before `anchor`, begins."""
        if self._reversed is None:
            self._reversed = self.text[::-1]
        mirrored = len(self.text) - anchor
        found = pattern.match(self._reversed, mirrored)
        return anchor - (found.end() - mirrored) if found else anchor


_Reader = Callable[[_Context, int, int], tuple[list[int], int | None]]


class _Anchored:
    """The earliest match of one anchored alternative at or after a position.

    Positions only ever grow, so an anchor passed over is never read again, and each one is
    read once.
    """

    __slots__ = ("_anchor", "_at", "_context", "_end", "_read", "_starts")

    def __init__(self, context: _Context, anchor: str, read: _Reader) -> None:
        self._context = context
        self._anchor = anchor
        self._read = read
        self._at = context.text.find(anchor)
        self._starts: list[int] | None = None
        self._end: int | None = None

    def find(self, position: int) -> tuple[int, int] | None:
        while self._at != -1:
            if self._at > position:
                if self._starts is None:
                    self._starts, self._end = self._read(self._context, self._at, position)
                index = bisect.bisect_left(self._starts, position)
                if self._end is not None and index < len(self._starts):
                    return self._starts[index], self._end
            self._at = self._context.text.find(self._anchor, self._at + 1)
            self._starts = None
        return None


def _scheme_at(context: _Context, colon: int, position: int) -> tuple[list[int], int | None]:
    """The admitted starts of a scheme ending at `colon`, at or after `position`, and the end.

    A start is an ASCII letter at a word boundary. Inside the stretch every character is a
    letter, a digit or one of `+.-`, so a letter is at a boundary exactly when one of those
    three stands before it; at the first position the boundary is asked of the text itself.
    """
    text = context.text
    first = max(position, context.stretch(_SCHEME_CHARS, colon))
    starts = [m.start() + 1 for m in _SCHEME_INNER_START.finditer(text, first, colon)]
    if first < colon and text[first] in _LETTERS and _BOUNDARY.match(text, first):
        starts.insert(0, first)
    if not starts:
        return starts, None
    if text.startswith("//", colon + 1):
        return starts, context.tail_stop(colon + 3)
    # The head cannot hold `@` or `/`, so it ends at the first character it cannot hold, and
    # the opaque branch matches only if that character is one of the two.
    head_end = context.head_stop(colon + 1)
    if head_end < len(text) and text[head_end] in "@/":
        return starts, context.tail_stop(head_end + 1)
    return starts, None


def _address_at(context: _Context, at: int, position: int) -> tuple[list[int], int | None]:
    """The admitted starts of an address whose `@` is at `at`, at or after `position`, and
    the end.

    The local part before `@` is the longest dot-atom ending there, so a start is any character
    of it that a local part may begin with and that stands at a word boundary.
    """
    text = context.text
    first = max(position, context.stretch(_LOCAL_REVERSED, at))
    starts = [
        boundary.start()
        for boundary in _BOUNDARY.finditer(text, first, at)
        if boundary.start() < at and text[boundary.start()] in _LOCAL_CHARS
    ]
    if not starts:
        return starts, None
    host = _HOST_AT.match(text, at + 1)
    return starts, host.end() if host else None


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
