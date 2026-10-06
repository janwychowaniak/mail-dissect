"""Defanged forms: SPEC §11.3, `[D28]`.

A defanged form is read by re-arming the whole unit first — every bracket marker of the table
replaced by what it stands for — and reading the result with the grammar every other text is
read with. A candidate whose range holds a marker is `defanged`, and its `value_raw` is that
range as written. Until 0.7.0 a marker was grown outwards over a fixed set of characters to a
token that then had to be one candidate whole, which lost the form after a hyphen, a period or
a bracket, and cut or distorted what the set did not reach (F22).
"""

from __future__ import annotations

from pathlib import Path

import builders as b
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

REGRESSIONS = Path(__file__).parent / "regressions"

# A defanged form is re-armed and marked. Each line of the saved message is one form, written
# directly after a hyphen or a period.
DEFANGED_AFTER_A_MARK = REGRESSIONS / "2026-10-01-defanged-after-a-hyphen-or-a-period.eml"
RE_ARMED = [
    ("domain", "one.example.net", "one[.]example[.]net"),
    ("url", "http://two.example.net/path", "hxxp://two[.]example[.]net/path"),
    ("domain", "two.example.net", "hxxp://two[.]example[.]net/path"),
    ("email", "user@three.example.net", "user[at]three[.]example[.]net"),
    ("domain", "three.example.net", "user[at]three[.]example[.]net"),
    ("ip", "192.0.2.201", "192[.]0[.]2[.]201"),
    ("domain", "four.example.net", "four[.]example[.]net"),
]


def _defanged(client: TestClient, raw: bytes) -> list[tuple[str, str, str]]:
    found = dissect(client, raw)["messages"][0]["observables"]
    return [(o["type"], o["value"], o["value_raw"]) for o in found if o["defanged"]]


def _found(client: TestClient, text: str) -> list[tuple[str, str, str, bool]]:
    raw = b.message({"Subject": "s"}, body=f"see {text} now".encode())
    found = dissect(client, raw)["messages"][0]["observables"]
    return [(o["type"], o["value"], o["value_raw"], o["defanged"]) for o in found]


def test_a_defanged_form_directly_after_a_hyphen_or_a_period(client: TestClient) -> None:
    """The defect listed in `CHANGELOG.md` until 0.7.0: the mark in front was grown into the
    token, and the token as a whole was no candidate."""
    assert _defanged(client, DEFANGED_AFTER_A_MARK.read_bytes()) == RE_ARMED


def test_the_defanged_forms_are_returned_after_a_space(client: TestClient) -> None:
    """The control: the saved message with a space put after each leading hyphen or period,
    which 0.6.0 returned too."""
    raw = DEFANGED_AFTER_A_MARK.read_bytes()
    assert raw.count(b"\r\n-") == 4 and raw.count(b"\r\n.") == 1
    spaced = raw.replace(b"\r\n-", b"\r\n- ").replace(b"\r\n.", b"\r\n. ")
    assert _defanged(client, spaced) == RE_ARMED


@pytest.mark.parametrize("left, right", [("(", ")"), ("[", "]"), ("{", "}"), (":", ":")])
def test_a_defanged_form_inside_brackets_or_after_a_colon(
    client: TestClient, left: str, right: str
) -> None:
    """The same mechanism lost the form after any character of the set it grew over."""
    assert _found(client, f"{left}one[.]example[.]net{right}") == [
        ("domain", "one.example.net", "one[.]example[.]net", True)
    ]


def test_what_the_old_set_cut_or_distorted_comes_back_whole(client: TestClient) -> None:
    """0.6.0 returned `…/p`, `…/` and `tag@three.example.net` here, the growth stopping at a
    character outside its set."""
    for text, value in (
        ("hxxp://two[.]example[.]net/p?q=1&r=2", "http://two.example.net/p?q=1&r=2"),
        ("hxxp://two[.]example[.]net/~user", "http://two.example.net/~user"),
    ):
        assert _found(client, text)[0] == ("url", value, text, True)
    assert _found(client, "first.last+tag[at]three[.]example[.]net")[0] == (
        "email",
        "first.last+tag@three.example.net",
        "first.last+tag[at]three[.]example[.]net",
        True,
    )


def test_a_candidate_reads_as_its_plain_twin(client: TestClient) -> None:
    """A candidate without a marker inside it is an ordinary one, and nothing is read that the
    same text written plainly would not give: 0.6.0 gave `cher.de` for `bücher[.]de`, and
    nothing at all for the first domain here."""
    assert _found(client, "one.example.com(two[.]example[.]net)") == [
        ("domain", "one.example.com", "one.example.com", False),
        ("filename", "one.example.com", "one.example.com", False),
        ("domain", "two.example.net", "two[.]example[.]net", True),
    ]
    assert _found(client, "bücher[.]de") == _found(client, "bücher.de") == []


def test_value_raw_is_the_candidate_s_own_range(client: TestClient) -> None:
    """Without the hyphen in front or the one behind, which trimming takes off either way."""
    assert _found(client, "-one[.]example[.]net-") == [
        ("domain", "one.example.net", "one[.]example[.]net", True)
    ]


def test_a_marker_left_off_the_end_is_punctuation(client: TestClient) -> None:
    """A trailing `[.]` stands for a period, which a candidate leaves off, so the candidate
    holds no marker and is the plain one; 0.6.0 returned it `defanged`, with the marker in
    `value_raw`. The grammar leaves the period out of `www.x.co`, and trimming takes it off a
    path: the second is where `value_raw` has to end where trimming ended the value."""
    assert (
        _found(client, "www.x.co[.]")
        == _found(client, "www.x.co.")
        == [("url", "www.x.co", "www.x.co", False), ("domain", "www.x.co", "www.x.co", False)]
    )
    url = "http://a.example.net/x"
    assert (
        _found(client, f"{url}[.]")
        == _found(client, f"{url}.")
        == [("url", url, url, False), ("domain", "a.example.net", url, False)]
    )


def test_a_defanged_scheme_is_re_armed_where_a_scheme_stands(client: TestClient) -> None:
    """At the start of a URL with a scheme, the whole scheme, in any case, with or without a
    bracket marker beside it. `fxp.example.net` is a host and stays one, and in
    `x-hxxp://…` the scheme is `x-hxxp`, so only its host is re-armed; `fxpa` is a scheme of
    its own, not `fxp` with a letter after it."""
    assert _found(client, "hxxp://example.net/x")[0] == (
        "url",
        "http://example.net/x",
        "hxxp://example.net/x",
        True,
    )
    assert _found(client, "HXXPS://a[.]example[.]net/")[0][1] == "https://a.example.net/"
    assert _found(client, "fxp://a.example.net/f")[0][1] == "ftp://a.example.net/f"
    assert _found(client, "fxp[.]example[.]net") == [
        ("domain", "fxp.example.net", "fxp[.]example[.]net", True)
    ]
    assert _found(client, "fxpa://a.example.net/f")[0] == (
        "url",
        "fxpa://a.example.net/f",
        "fxpa://a.example.net/f",
        False,
    )
    assert _found(client, "x-hxxp://a[.]example[.]net")[0] == (
        "url",
        "x-hxxp://a.example.net",
        "x-hxxp://a[.]example[.]net",
        True,
    )


def test_a_marker_is_written_in_the_table_s_case(client: TestClient) -> None:
    """`[AT]` is no marker, so the address is not read, and its domain is, as the same text
    with `.` for each `[.]` gives it."""
    assert _found(client, "user[AT]three[.]example[.]net") == [
        ("domain", "three.example.net", "three[.]example[.]net", True)
    ]


def test_a_defanged_range_gives_both_ends(client: TestClient) -> None:
    """`[D26]` holds for the defanged spelling: a range written with `...` returns both ends."""
    assert _found(client, "192[.]0[.]2[.]1...192[.]0[.]2[.]9") == [
        ("ip", "192.0.2.1", "192[.]0[.]2[.]1", True),
        ("ip", "192.0.2.9", "192[.]0[.]2[.]9", True),
    ]
