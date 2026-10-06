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

# SPEC §11.3: the closed defang table. A unit is rewritten with it before the grammar reads it,
# and where each replacement stands is kept, so that `value_raw` and the order of first
# occurrence are those of the text as written [D28].
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
# [D31] A URL has two grammars, as RFC 3986 has: one for the authority and one for the path,
# query and fragment. A `,` or a `)` may stand in the path, query or fragment of a URL with an
# authority, and ends any other part; a comma directly before another `scheme://` ends the URL.
# `[` and `]` end a URL anywhere but in an IP-literal host directly after `//`.
_URL_PCHAR = r"(?:[^\s<>\"'\[\],]|,(?![A-Za-z][A-Za-z0-9+.-]*://))"
_URL_PATH = rf"(?:[/?#]{_URL_PCHAR}*)?"
# [D32] In text, a URL's host is labels or an IP literal, not RFC 3986's reg-name, so that
# markup glued to a host (`**…**`, `|…|`) does not become part of it. `%` is in a label so that
# a percent-encoded host is not cut in half; it gives no `domain` [D30].
_URL_HOSTLABEL = r"[\w%-]+"
_URL_HOSTPART = rf"(?:\[[0-9A-Fa-f:.]+\]|{_URL_HOSTLABEL}(?:\.{_URL_HOSTLABEL})*\.?)"
_URL_AUTH = rf"(?:[^\s<>\"'\[\]\),@/?#]*@)?{_URL_HOSTPART}(?::\d*)?"
# A URL with no authority (`mailto:`, `sip:`, `data:`) holds none of `[ ] ) ,`.
_URL_OPAQUE = r"[^\s<>\"'\[\]\),]*"
# Excludes `@` and `/` so the opaque-scheme branch has exactly one way to match:
# `tail [@/] tail` with the same class on both sides backtracks quadratically.
_URL_HEAD = r"[^\s<>\"'\[\]\),@/]*"
_LOCAL_PART = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"

# The order of these alternatives IS the contract for resolving overlaps (SPEC §11.2): the
# earliest match wins, and at the same position the earlier alternative wins.
#
# 1. A URI with a scheme. An opaque scheme must carry an `@` or a `/`, which is what separates
#    `mailto:a@example.com` from the `Note:this` in a sentence - a structural test, not a list
#    of schemes we happen to like.
_URL_SCHEME = (
    rf"(?P<url_scheme>\b[A-Za-z][A-Za-z0-9+.-]*:"
    rf"(?://{_URL_AUTH}{_URL_PATH}|{_URL_HEAD}[@/]{_URL_OPAQUE}))"
)
# 2. An address.
_EMAIL = rf"(?P<email>\b{_LOCAL_PART}@{_HOST})"
_OTHERS = "|".join(
    (
        # 3. A URL without a scheme: shorteners and `www.` are everyday mail content.
        rf"(?P<url_bare>\b(?:www\.{_HOST}(?::\d*)?{_URL_PATH}|{_HOST}/{_URL_PCHAR}*))",
        # 4/5. Loose shapes, validated by a real address parser rather than by the regex.
        r"(?P<ipv6>(?<![:.\w])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:.]{0,45})",
        #    [D26]: a label character (`\w`: a letter, a digit or an underscore, in any
        #    script) next to the address rules it out, and so does one on the far side
        #    of a period or a hyphen that touches it - the head of a host name, the tail
        #    of a version. A period or a hyphen with anything else beyond it is
        #    punctuation, on either side.
        r"(?P<ipv4>(?<!\w)(?<!\w[.-])\d{1,3}(?:\.\d{1,3}){3}(?!\w|[.-]\w))",
        # 6. A written-down digest.
        r"(?P<hash>\b[0-9a-fA-F]{32}(?:[0-9a-fA-F]{8})?(?:[0-9a-fA-F]{24})?(?:[0-9a-fA-F]{64})?\b)",
        # 7. A token the registries decide about: a domain, a filename, both, or neither.
        rf"(?P<token>\b{_LABEL}(?:\.{_LABEL})+)",
    )
)
# The whole alternation: what `_matches` reads, written as one pattern, against which the test
# of exact rewrites compares it.
_MASTER = re.compile(f"{_URL_SCHEME}|{_EMAIL}|{_OTHERS}")
# The scan finds a URI with a scheme and an address by their anchors (`_anchored`), and the
# rest with this.
_REST = re.compile(_OTHERS)
# [D28]: a defanged form is read by re-arming the whole unit first - every bracket marker
# replaced by what it stands for - and reading the result with the same grammar as any other
# text. A candidate whose range holds a marker is `defanged`, and its `value_raw` is that range
# as it was written. Markers are written in the table's case only; a scheme is re-armed at the
# start of a URL with a scheme, in any case.
_MARKER_SEARCH = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]|\[at\]|\(at\)|\[@\]")
_REPLACEMENT = dict(_DEFANG_REPLACEMENTS)

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
# [D30]: a value derived from another candidate is checked against its type. A `domain` is
# labels, letters and digits in any script, `_` (F12) and `-`, separated by periods; an
# `email` is a local part by the address grammar and a domain of labels. One label is labels
# too: a host that is a public suffix and nothing more was a `domain` before, and stays one.
_DOMAIN_SHAPE = re.compile(r"[\w-]+(?:\.[\w-]+)*")
_LOCAL_SHAPE = re.compile(_LOCAL_PART)
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
    # The same places as a set, so that asking whether one is listed costs the same for the
    # first source as for the twenty-thousandth.
    places: set[Source] = field(default_factory=set, repr=False, compare=False)


class Places:
    """How many more places `observables[]` may list, across one whole response `[D37]`.

    A place is one entry of an observable's `sources`, so a value in many places counts each,
    and a new value counts its first. Shared by the collectors of every message, so nesting
    does not multiply it.
    """

    __slots__ = ("left",)

    def __init__(self, places: int) -> None:
        self.left = places

    def take(self) -> bool:
        if self.left <= 0:
            return False
        self.left -= 1
        return True


class Collector:
    """Append-only, so the deterministic core of the list never moves `[D9]`.

    Candidates from an optional tool can only ever extend the tail: a consumer comparing two
    dissections of the same message, one with the text extractor and one without, sees the
    same entries in the same positions and a longer list.
    """

    __slots__ = (
        "_order",
        "_places",
        "_registries",
        "_seen",
        "_should_stop",
        "stopped",
        "truncated",
    )

    def __init__(
        self,
        registries: Registries,
        should_stop: Callable[[], bool] | None = None,
        places: Places | None = None,
    ) -> None:
        self._registries = registries
        self._seen: dict[tuple[str, str], Candidate] = {}
        self._order: list[Candidate] = []
        # The deadline, asked before every chunk and every address `[D10]`. Once it has said
        # stop, nothing more is added: the list ends where the scan stopped.
        self._should_stop = should_stop
        self._places = places
        self.stopped = False
        # Something the material holds was not read: the scan stopped, or a run was skipped.
        self.truncated = False

    def feed_text(self, text: str, source: Source) -> None:
        """Scan a blob; overlapping matches are resolved once, in document order.

        A defanged form is read as the form it stands for, re-armed with the rest of its unit
        before the grammar reads anything `[D28]`, so it is found where the form itself would
        be, after a hyphen, a period or a parenthesis alike.
        """
        for chunk in _chunks(text):
            if self._stop():
                return
            for piece in self._without_long_runs(chunk):
                for kind, value, raw, defanged in _readings(piece):
                    self._classify(kind, value, raw, source, defanged=defanged)

    def feed_url(self, href: str, source: Source) -> None:
        """An address taken from an anchor or a resource, which needs no grammar to find."""
        if not href or self._stop():
            return
        self._emit(href, href, "url", source)
        self._fan_out_url(href, href, source, defanged=False)

    def finish(self) -> list[Candidate]:
        return self._order

    def _take_place(self) -> bool:
        if self._places is None or self._places.take():
            return True
        self.stopped = True
        self.truncated = True
        return False

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
    def _classify(
        self, kind: str, value: str, raw: str, source: Source, *, defanged: bool = False
    ) -> None:
        """One reading: `value` is what it stands for, `raw` how it was written."""
        if kind in ("url_scheme", "url_bare"):
            url = _canonical_url(value)
            self._emit(url, raw, "url", source, defanged=defanged)
            self._fan_out_url(url, raw, source, defanged=defanged)
        elif kind == "email":
            self._emit_email(value, raw, source, defanged=defanged)
        elif kind == "ipv4" or kind == "ipv6":
            address = _valid_ip(value)
            if address is not None:
                self._emit(address[0], raw, "ip", source, subtype=address[1], defanged=defanged)
        elif kind == "hash":
            subtype = _HASH_SUBTYPES.get(len(value))
            if subtype is not None:
                self._emit(value.lower(), raw, "hash", source, subtype=subtype, defanged=defanged)
        elif kind == "token":
            self._classify_token(value, raw, source, defanged=defanged)

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
            # RFC 6068: the address part is a list of recipients separated by commas, and each
            # is taken only when it is one address. A period at the end of its domain is read
            # as it is in a host, which loses it.
            for recipient in parts.path.split(","):
                local, at, domain = recipient.rpartition("@")
                if (
                    at
                    and _LOCAL_SHAPE.fullmatch(local)
                    and _DOMAIN_SHAPE.fullmatch(domain.rstrip("."))
                ):
                    self._emit_email(recipient, raw, source, defanged=defanged)

    def _emit_host(self, host: str, raw: str, source: Source, *, defanged: bool) -> None:
        address = _valid_ip(host)
        if address is not None:
            self._emit(address[0], raw, "ip", source, subtype=address[1], defanged=defanged)
        elif _DOMAIN_SHAPE.fullmatch(host) and self._registries.public_suffix(host) is not None:
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
        """Deduplicate by `(value, type)`; count every occurrence, list distinct places.

        Once the places of the response are spent `[D37]`, the list stops as it does at the
        deadline: no entry, place or occurrence is added after that, so the three agree.
        """
        if self.stopped:
            return
        key = (value, type_)
        candidate = self._seen.get(key)
        if (candidate is None or source not in candidate.places) and not self._take_place():
            return
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
        if source not in candidate.places:
            candidate.places.add(source)
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
    """Every span the grammar takes, in document order, as written: kind and text."""
    armed, marks, removed = _armed(text)
    return [
        (kind, text[_written(start, marks, removed) : _written(end, marks, removed)])
        for start, end, kind in _matches(armed)
    ]


def _readings(text: str) -> Iterator[tuple[str, str, str, bool]]:
    """Each candidate of a unit: its kind, what it stands for, how it was written, and
    whether re-arming made the difference `[D28]`."""
    armed, marks, removed = _armed(text)
    for start, end, kind in _matches(armed):
        value = _trim(armed[start:end])
        if not value:
            continue
        end = start + len(value)
        defanged = _holds_marker(marks, start, end)
        if kind == "url_scheme":
            value, rearmed = _rearm_scheme(value)
            defanged = defanged or rearmed
        raw = text[_written(start, marks, removed) : _written(end, marks, removed)]
        yield kind, value, raw, defanged


def _armed(text: str) -> tuple[str, list[int], list[int]]:
    """The text with every bracket marker replaced, where each replacement stands in it, and
    how many characters were removed before each.

    Only the markers are remembered, not an offset for every character, which on a text of
    megabytes would be megabytes again; a unit with no marker is handed back as it is.
    """
    marks: list[int] = []
    removed = [0]
    pieces: list[str] = []
    last = 0
    for marker in _MARKER_SEARCH.finditer(text):
        pieces.append(text[last : marker.start()])
        marks.append(marker.start() - removed[-1])
        removed.append(removed[-1] + len(marker.group()) - 1)
        pieces.append(_REPLACEMENT[marker.group()])
        last = marker.end()
    if not marks:
        return text, marks, removed
    pieces.append(text[last:])
    return "".join(pieces), marks, removed


def _written(position: int, marks: list[int], removed: list[int]) -> int:
    """Where a position of the re-armed text stands in the text as written."""
    return position + removed[bisect.bisect_left(marks, position)]


def _holds_marker(marks: list[int], start: int, end: int) -> bool:
    index = bisect.bisect_left(marks, start)
    return index < len(marks) and marks[index] < end


def _rearm_scheme(value: str) -> tuple[str, bool]:
    """A defanged scheme, read where the grammar reads a scheme: the whole of it, before its
    colon, in any case (RFC 3986 §3.1). `fxp.example.net` is a host and stays one."""
    lowered = value.lower()
    for written, real in _DEFANG_SCHEMES:
        if lowered.startswith(f"{written}:"):
            return real + value[len(written) :], True
    return value, False


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
_HEAD_STOP = re.compile(r"[\s<>\"'\[\]\),@/]")
_OPAQUE_STOP = re.compile(r"[\s<>\"'\[\]\),]")
_USERINFO_STOP = re.compile(r"[\s<>\"'\[\]\),@/?#]")
# The path ends at a character it cannot hold, or at a comma directly before another
# `scheme://`. Each comma's look ahead stops at the next comma, so one search is linear.
_PATH_END = re.compile(r"[\s<>\"'\[\]]|,(?=[A-Za-z][A-Za-z0-9+.-]*://)")
_URL_HOST_AT = re.compile(_URL_HOSTPART)
_PORT_AT = re.compile(r"(?::\d*)?")
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

    __slots__ = ("_reversed", "head_stop", "opaque_stop", "path_stop", "text", "userinfo_stop")

    def __init__(self, text: str) -> None:
        self.text = text
        self._reversed: str | None = None
        self.head_stop = _Stop(text, _HEAD_STOP)
        self.opaque_stop = _Stop(text, _OPAQUE_STOP)
        self.userinfo_stop = _Stop(text, _USERINFO_STOP)
        self.path_stop = _Stop(text, _PATH_END)

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
        end = _authority_and_path(context, colon + 3)
        if end is not None:
            return starts, end
    # The head cannot hold `@` or `/`, so it ends at the first character it cannot hold, and
    # the opaque branch matches only if that character is one of the two. It is also what
    # reads `scheme://` whose authority is no host, from its first `/`.
    head_end = context.head_stop(colon + 1)
    if head_end < len(text) and text[head_end] in "@/":
        return starts, context.opaque_stop(head_end + 1)
    return starts, None


def _authority_and_path(context: _Context, start: int) -> int | None:
    """Where `{_URL_AUTH}{_URL_PATH}` matched at `start` ends, or None.

    The userinfo is tried first, as the pattern tries it: it holds no `@`, so it is there only
    when the first character it cannot hold is `@`, and when no host follows that `@` the
    pattern goes back and reads a host from `start`.
    """
    text = context.text
    userinfo_end = context.userinfo_stop(start)
    if userinfo_end < len(text) and text[userinfo_end] == "@":
        end = _host_and_path(context, userinfo_end + 1)
        if end is not None:
            return end
    return _host_and_path(context, start)


def _host_and_path(context: _Context, start: int) -> int | None:
    text = context.text
    host = _URL_HOST_AT.match(text, start)
    if host is None:
        return None
    end = _PORT_AT.match(text, host.end()).end()  # type: ignore[union-attr]
    if end < len(text) and text[end] in "/?#":
        end = context.path_stop(end + 1)
    return end


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


def _trim(raw: str) -> str:
    """Strip trailing punctuation a sentence leaves behind, parenthesis-balance aware.

    A character comes off the end while it is punctuation, or a closer with fewer openers
    than closers before it. One pass from the end with the counts kept as it goes, and one
    slice: cutting a character at a time and counting again was quadratic in a long tail.
    """
    closers = {closer: raw.count(closer) for closer in _CLOSERS}
    openers = {closer: raw.count(opener) for closer, opener in _CLOSERS.items()}
    end = len(raw)
    while end:
        last = raw[end - 1]
        if last in _TRAILING_PUNCTUATION:
            end -= 1
        elif last in _CLOSERS and openers[last] < closers[last]:
            closers[last] -= 1
            end -= 1
        else:
            break
    return raw[:end]


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
    # An IPv6 address stands in brackets in a URL, and keeps them in the canonical form.
    host = f"[{parts.host}]" if ":" in parts.host else parts.host
    authority = f"{host}:{parts.port}" if parts.port else host
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
