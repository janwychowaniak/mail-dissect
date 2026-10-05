"""Each linear rewrite reads exactly what the pattern it replaced read: SPEC §11.2, F22.

A pattern or a loop that was quadratic on a long run was rewritten to read each run once. The
pattern stays here as the definition of the reading, and each rewrite is compared with it on
generated inputs that are short, so the old way is cheap to run. Each test also checks that the
inputs reach the branches that decide anything, since a comparison on inputs that match
nothing is a comparison of two empty lists.
"""

from __future__ import annotations

import random
import re

from mail_dissect import headers, htmlscan, observables

SEED = 20261005


def _strings(alphabet: list[str], count: int, longest: int) -> list[str]:
    rng = random.Random(SEED)
    return [
        "".join(rng.choice(alphabet) for _ in range(rng.randint(1, longest))) for _ in range(count)
    ]


def test_the_scan_finds_what_the_alternation_finds() -> None:
    """The scan finds a URL with a scheme and an address by their anchors, and the rest with
    one pattern; together they give what one search for the whole alternation gives."""
    alphabet = [*"aAzZ19._-+:@/?#=&%~!*'\"()[]{}<>,;|`^$_ \n", "é", chr(0x661), "..", "://"]
    alphabet += ["@a.b"]
    alphabet += ["a.b", "www.", "mailto:", "x.co", "::", "1.2.3.4"]
    texts = _strings(alphabet, 4000, 30)

    def by_pattern(text: str) -> list[tuple[int, int, str | None]]:
        return [(m.start(), m.end(), m.lastgroup) for m in observables._MASTER.finditer(text)]

    found = [list(observables._matches(text)) for text in texts]
    kinds = [kind for matches in found for _, _, kind in matches]
    assert kinds.count("url_scheme") > 300 and kinds.count("email") > 300
    assert found == [by_pattern(text) for text in texts]


# The pattern CSS addresses were read with until 0.7.0.
CSS_URL = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)""", re.IGNORECASE)


def test_css_addresses_are_read_as_the_pattern_read_them() -> None:
    alphabet = ["url(", "URL(", "uRl(", '"', "'", ")", "(", " ", "\n", "\t", "a", "b.png", "/", ";"]
    texts = _strings(alphabet, 4000, 20)

    def by_pattern(css: str) -> list[str]:
        return [m.group(1) or m.group(2) or m.group(3) or "" for m in CSS_URL.finditer(css)]

    found = [list(htmlscan._css_urls(css)) for css in texts]
    values = [value for values in found for value in values if value]
    assert sum('"' in value or "'" in value for value in values) > 100
    assert len(values) > 600
    assert [[value or "" for value in values] for values in found] == [
        by_pattern(css) for css in texts
    ]


def _trim_one_at_a_time(raw: str) -> str:
    """The trimming rule as it was written until 0.7.0: a character at a time."""
    value = raw
    while value:
        last = value[-1]
        if last in observables._TRAILING_PUNCTUATION:
            value = value[:-1]
            continue
        if last in observables._CLOSERS and value.count(observables._CLOSERS[last]) < value.count(
            last
        ):
            value = value[:-1]
            continue
        break
    return value


def test_trimming_cuts_what_cutting_one_at_a_time_cut() -> None:
    alphabet = [*"a/.,;:!?\"'()[]{}<>x"]
    texts = ["http://a.example.net/" + tail for tail in _strings(alphabet, 4000, 15)]
    trimmed = [observables._trim(text) for text in texts]
    assert sum(t != text for t, text in zip(trimmed, texts, strict=True)) > 2000
    assert sum(t.endswith((")", "]", "}")) for t in trimmed) > 200
    assert trimmed == [_trim_one_at_a_time(text) for text in texts]


# The pattern `Received` fields were read with until 0.7.0.
RECEIVED_TOKEN = re.compile(
    r"\b(from|by|with|id|for|via)\s+([^\s;]+(?:\s*\([^)]*\))?)", re.IGNORECASE
)


def _received_as_it_was(value: str) -> headers.Hop:
    """`parse_received` as it was until 0.7.0, with the pattern above."""
    body, _, timestamp = value.rpartition(";")
    if not body:
        body, timestamp = value, ""
    fields: dict[str, str] = {}
    for match in RECEIVED_TOKEN.finditer(body):
        fields.setdefault(match.group(1).lower(), match.group(2).strip())
    from_host, from_ip = headers._split_host_and_ip(fields.get("from"))
    return headers.Hop(
        from_host=from_host,
        from_ip=from_ip,
        by_host=headers._bare(fields.get("by")),
        with_=headers._bare(fields.get("with")),
        id=headers._bare(fields.get("id")),
        for_=headers._bare(fields.get("for")),
        timestamp=timestamp.strip() or None,
    )


def test_received_is_read_as_the_pattern_read_it() -> None:
    alphabet = ["from ", "by ", "with ", "id ", "for ", "via ", "FROM ", "a.example.net", "(", ")"]
    alphabet += ["[192.0.2.1]", " ", "  ", ";", "x", "\t", "(c)", "(192.0.2.7)"]
    values = _strings(alphabet, 4000, 12)
    hops = [headers.parse_received(value) for value in values]
    fields = [
        value
        for hop in hops
        for value in (hop.by_host, hop.with_, hop.id, hop.for_, hop.from_host, hop.from_ip)
    ]
    assert sum(value is not None for value in fields) > 1200
    assert sum(hop.from_ip is not None for hop in hops) > 50
    assert hops == [_received_as_it_was(value) for value in values]


# The pattern `Authentication-Results` parameters were read with until 0.7.0.
AUTH_PARAM = re.compile(r"([A-Za-z0-9_.-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)")


def test_authentication_parameters_are_read_as_the_pattern_read_them() -> None:
    alphabet = ["a", "b.c", "-", "_", "=", " ", '"', "x y", ";", "smtp.mailfrom", "pass", "@"]
    chunks = _strings(alphabet, 4000, 15)

    def pairs(pattern: re.Pattern[str], chunk: str) -> list[tuple[str, str]]:
        return [(m.group(1), m.group(2)) for m in pattern.finditer(chunk)]

    read = [pairs(headers._AUTH_PARAM, chunk) for chunk in chunks]
    assert sum(len(found) for found in read) > 700
    assert read == [pairs(AUTH_PARAM, chunk) for chunk in chunks]
