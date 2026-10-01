"""What may stand next to an IPv4 address: SPEC §11.2, `[D26]`. Acceptance case 71.

A period or a hyphen that touches the address is punctuation, unless a label character — a
letter, a digit or an underscore, in any script — continues on its far side. So an address
that ends a sentence is a candidate, and four numbers at the head of a host name are not.

Until 0.5.0 a period or a hyphen on either side ruled the address out whatever stood beyond
it, and the candidate was gone before the parser that validates it saw it (F20).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import builders as b
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

REGRESSIONS = Path(__file__).parent / "regressions"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


@dataclass(frozen=True)
class Saved:
    """One saved message and the `ip` candidates it yields, in the order they are written."""

    file: str
    ips: list[str]
    occurrences: dict[str, int] = field(default_factory=dict)
    body_domains: list[str] | None = None

    @property
    def raw(self) -> bytes:
        return (REGRESSIONS / self.file).read_bytes()


SAVED: tuple[Saved, ...] = (
    Saved(
        "2026-10-01-ipv4-before-a-period.eml",
        ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"],
    ),
    Saved("2026-10-01-ipv4-before-a-period-in-html.eml", ["192.0.2.6"]),
    Saved("2026-10-01-ipv4-before-a-period-in-a-header.eml", ["192.0.2.7", "192.0.2.8"]),
    Saved(
        "2026-10-01-ipv4-bare-and-before-a-period.eml",
        ["192.0.2.9"],
        occurrences={"192.0.2.9": 2},
    ),
    Saved("2026-10-01-ipv4-after-a-period.eml", ["192.0.2.11", "192.0.2.12", "192.0.2.13"]),
    Saved(
        "2026-10-01-ipv4-next-to-a-hyphen.eml",
        ["192.0.2.21", "192.0.2.22", "192.0.2.23", "192.0.2.24"],
    ),
    Saved(
        "2026-10-01-ipv4-range-with-a-hyphen-and-a-space.eml",
        ["192.0.2.41", "192.0.2.49", "192.0.2.51", "192.0.2.59"],
    ),
    Saved(
        "2026-10-01-ipv4-range-with-periods.eml",
        ["192.0.2.61", "192.0.2.69", "192.0.2.71", "192.0.2.79", "192.0.2.81", "192.0.2.89"],
    ),
    # The two that must not move. A range with nothing around its hyphen returns neither end:
    # half a range reads as a single address, and that is worse than silence.
    Saved("2026-10-01-ipv4-range-with-a-bare-hyphen.eml", []),
    # Four numbers inside a longer token are not an address, and the three host names among
    # them are still the domains they were.
    Saved(
        "2026-10-01-ipv4-inside-a-longer-token.eml",
        [],
        body_domains=[
            "192.0.2.101.example.net",
            "192.0.2.102-static.example.net",
            "192.0.2.103.next",
        ],
    ),
)


def _observables(client: TestClient, body_text: str) -> list[dict]:
    """Candidates from a message whose headers carry none of their own."""
    raw = b.message({"Subject": "a plain subject"}, body=body_text.encode())
    return dissect(client, raw)["messages"][0]["observables"]


def _found(client: TestClient, body_text: str) -> list[tuple[str, str]]:
    return [(o["type"], o["value"]) for o in _observables(client, body_text)]


@pytest.mark.parametrize("case", SAVED, ids=lambda case: case.file)
def test_a_saved_message(client: TestClient, case: Saved) -> None:
    """The reported shapes and their controls, as bytes `[D18]`.

    `value_raw` is the address and nothing else: the mark next to it is not part of the
    candidate, the same way a domain before a period is returned without it.
    """
    found = dissect(client, case.raw)["messages"][0]["observables"]
    ips = [o for o in found if o["type"] == "ip"]
    assert [o["value"] for o in ips] == case.ips
    assert [o["value_raw"] for o in ips] == case.ips
    assert all(o["subtype"] == "ipv4" and not o["defanged"] for o in ips)
    assert [o["occurrences"] for o in ips] == [case.occurrences.get(ip, 1) for ip in case.ips]
    if case.body_domains is not None:
        from_the_body = [
            o["value"]
            for o in found
            if o["type"] == "domain" and any(s["kind"] != "header" for s in o["sources"])
        ]
        assert from_the_body == case.body_domains


def test_every_source_is_read_by_the_same_rule(client: TestClient) -> None:
    """One scanner, one rule: a header value, a text body and an HTML body alike."""

    def places(file: str) -> dict[str, list[tuple[str, str | None]]]:
        found = dissect(client, (REGRESSIONS / file).read_bytes())["messages"][0]["observables"]
        return {
            o["value"]: [(s["kind"], s["header_name"]) for s in o["sources"]]
            for o in found
            if o["type"] == "ip"
        }

    assert places("2026-10-01-ipv4-before-a-period-in-a-header.eml") == {
        "192.0.2.7": [("header", "x-note")],
        "192.0.2.8": [("header", "x-trailer")],
    }
    assert places("2026-10-01-ipv4-before-a-period.eml")["192.0.2.1"] == [("body_text", None)]
    assert places("2026-10-01-ipv4-before-a-period-in-html.eml") == {
        "192.0.2.6": [("body_html", None)]
    }


@pytest.mark.parametrize(
    "text",
    [
        "x 192.0.2.1. y",
        "x 192.0.2.1.",
        "x 192.0.2.1.. y",
        "x (192.0.2.1.) y",
        "x 192.0.2.1., y",
        'x "192.0.2.1." y',
        "x 192.0.2.1.\ty",
        "x 192.0.2.1.-y",
        "x 192.0.2.1- y",
        "x 192.0.2.1-",
        "x 192.0.2.1-. y",
        "x .192.0.2.1 y",
        ".192.0.2.1",
        "x ..192.0.2.1 y",
        "x -192.0.2.1 y",
        "-192.0.2.1",
        "x --192.0.2.1 y",
        "x (-192.0.2.1) y",
        "x .-192.0.2.1 y",
    ],
)
def test_a_mark_with_no_label_character_beyond_it_is_punctuation(
    client: TestClient, text: str
) -> None:
    """White space, the end of the text, a bracket, another mark: the address stands."""
    found = _observables(client, text)
    assert [(o["type"], o["value"], o["value_raw"]) for o in found] == [
        ("ip", "192.0.2.1", "192.0.2.1")
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A label character on the far side of the period or the hyphen: a longer token.
        ("x 192.0.2.1.example.net y", [("domain", "192.0.2.1.example.net")]),
        ("x 192.0.2.1-static.example.net y", [("domain", "192.0.2.1-static.example.net")]),
        ("x 192.0.2.1.Next y", [("domain", "192.0.2.1.next")]),
        ("x 192.0.2.1.5 y", []),
        ("x 192.0.2.1.5. y", []),
        ("x 192.0.2.1._y", []),
        ("x 192.0.2.1.é y", []),
        ("x 192.0.2.1-rc1 y", []),
        ("x 192.0.2.1-9 y", []),
        ("x 192.0.2.1-_ y", []),
        ("x 192.0.2.1-é y", []),
        ("x word-192.0.2.1 y", []),
        ("x 9-192.0.2.1 y", []),
        ("x under_-192.0.2.1 y", []),
        ("x é-192.0.2.1 y", []),
        (f"x {MD5}-192.0.2.1 y", [("hash", MD5)]),
        ("x end.192.0.2.1 y", []),
        ("x 5.192.0.2.1 y", []),
        ("x under_.192.0.2.1 y", []),
        ("x é.192.0.2.1 y", []),
        # A label character touching the address itself.
        ("x 192.0.2.1a y", []),
        ("x 192.0.2.1_ y", []),
        ("x 192.0.2.1é y", []),
        ("x v192.0.2.1 y", []),
        ("x _192.0.2.1 y", []),
        ("x é192.0.2.1 y", []),
    ],
)
def test_a_label_character_rules_the_address_out(
    client: TestClient, text: str, expected: list[tuple[str, str]]
) -> None:
    """A letter, a digit or an underscore, in any script — next to the address or beyond the mark.

    None of these returned an address before `[D26]` either. They are here because each one is
    what a looser rule would start returning: the head of a host name, the tail of a version.
    """
    assert _found(client, text) == expected


@pytest.mark.parametrize(
    ("text", "ends"),
    [
        ("x 192.0.2.1-192.0.2.9 y", []),
        ("x 192.0.2.1 - 192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1- 192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1 -192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1--192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1...192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1..192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1-.192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1.-192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
        ("x 192.0.2.1\N{EN DASH}192.0.2.9 y", ["192.0.2.1", "192.0.2.9"]),
    ],
)
def test_a_range_returns_both_ends_or_neither(
    client: TestClient, text: str, ends: list[str]
) -> None:
    """Never one end of two: half a range reads as a single address."""
    assert _found(client, text) == [("ip", end) for end in ends]


@pytest.mark.parametrize("last", ["123", "210"])
def test_a_mark_does_not_turn_an_address_into_a_file_name(client: TestClient, last: str) -> None:
    """`123` and `210` are file extensions in the registry, and they are also last numbers.

    Refused as an address because of the mark, `192.0.2.123.` fell through to the next
    alternative and came back as a `filename` (F20). The alternative for an address comes
    first (SPEC §11.2), so with the mark or without it the candidate is the address. Five
    numbers ending in the extension are the control: a file name, as before.
    """
    address = f"192.0.2.{last}"
    assert _found(client, f"x {address} y") == [("ip", address)]
    for text in (f"x {address}. y", f"x {address}- y", f"x -{address} y", f"x .{address} y"):
        assert _found(client, text) == [("ip", address)], text
    assert _found(client, f"x 192.0.2.1.{last} y") == [("filename", f"192.0.2.1.{last}")]


def test_a_hyphen_that_ends_a_line_is_punctuation_too(client: TestClient) -> None:
    """Accepted knowingly: if that hyphen was a hard wrap inside a host name, the address and
    the tail of the name both come back. A candidate, not a verdict."""
    assert _found(client, "x 192.0.2.1-\r\nstatic.example.net y") == [
        ("ip", "192.0.2.1"),
        ("domain", "static.example.net"),
    ]


def test_a_doubled_hyphen_is_a_mark_beyond_the_mark(client: TestClient) -> None:
    """The price of `a--b` returning both ends, paid by a host name nobody is likely to write.

    `192.0.2.1--static.example.net` was one host name to the domain grammar. What stands
    beyond the first hyphen is a hyphen, not a label character, so the address stands and the
    name comes back without its head. With one hyphen it is still the host name it was.
    """
    assert _found(client, "x 192.0.2.1--static.example.net y") == [
        ("ip", "192.0.2.1"),
        ("domain", "static.example.net"),
    ]
    assert _found(client, "x 192.0.2.1-static.example.net y") == [
        ("domain", "192.0.2.1-static.example.net")
    ]


@pytest.mark.parametrize(
    "text",
    [
        "x 192.0.2.1 y",
        "x 192.0.2.1, y",
        "x 192.0.2.1; y",
        "x 192.0.2.1: y",
        "x 192.0.2.1! y",
        "x 192.0.2.1? y",
        "x (192.0.2.1) y",
        "x [192.0.2.1] y",
        'x "192.0.2.1" y',
        "x 192.0.2.1:8080 y",
        "x key=192.0.2.1 y",
    ],
)
def test_the_other_marks_never_stood_in_the_way(client: TestClient, text: str) -> None:
    """The control for the whole file: these were returned before the rule and still are."""
    assert _found(client, text) == [("ip", "192.0.2.1")]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Half a range in three written forms: the left end only, as before.
        ("x 192.0.2.1:80-192.0.2.9:80 y", [("ip", "192.0.2.1")]),
        (
            "x 192.0.2.1/32-192.0.2.9/32 y",
            [("url", "192.0.2.1/32-192.0.2.9/32"), ("ip", "192.0.2.1")],
        ),
        ("x ::ffff:192.0.2.1-192.0.2.9 y", [("ip", "::ffff:192.0.2.1")]),
        # The IPv6 grammar is not part of the rule: a period before the address rules it out,
        # a period or a hyphen after it never did.
        ("x .2001:db8::1 y", []),
        ("x 2001:db8::1. y", [("ip", "2001:db8::1")]),
        ("x 2001:db8::1- y", [("ip", "2001:db8::1")]),
        # Four numbers a real parser refuses are no more an address before a period.
        ("x 999.1.1.1. y", []),
    ],
)
def test_what_was_measured_and_left(
    client: TestClient, text: str, expected: list[tuple[str, str]]
) -> None:
    """`[D26]` names these as left where they were, so that nobody takes them for a regression."""
    assert _found(client, text) == expected


def test_the_defanged_form_before_a_period_was_always_returned(client: TestClient) -> None:
    """The other half of the report: the same address, defanged, never needed the rule."""
    (only,) = _observables(client, "x 192[.]0[.]2[.]1. y")
    assert (only["type"], only["value"], only["value_raw"], only["defanged"]) == (
        "ip",
        "192.0.2.1",
        "192[.]0[.]2[.]1",
        True,
    )
