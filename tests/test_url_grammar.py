"""Where a URL found in text begins and ends: SPEC §11.2, `[D31]` and `[D32]`.

A URL has one grammar for its authority and another for its path, query and fragment, as
RFC 3986 has, and in text its host is labels or an IP literal. Until 0.7.0 one character class
covered the whole URL, so a URL was cut at the first `,`, `)` or `]` anywhere in it, and a host
took in whatever RFC 3986's reg-name allows, markup included.
"""

from __future__ import annotations

from pathlib import Path

import builders as b
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

REGRESSIONS = Path(__file__).parent / "regressions"


def _found(client: TestClient, text: str) -> list[tuple[str, str]]:
    raw = b.message({"Subject": "s"}, body=f"see {text} now".encode())
    return [(o["type"], o["value"]) for o in dissect(client, raw)["messages"][0]["observables"]]


def _urls(client: TestClient, text: str) -> list[str]:
    return [value for kind, value in _found(client, text) if kind == "url"]


@pytest.mark.parametrize(
    ("written", "url"),
    [
        ("https://en.example.org/wiki/Foo_(bar)", "https://en.example.org/wiki/Foo_(bar)"),
        ("https://example.net/?ids=1,2,3", "https://example.net/?ids=1,2,3"),
        ("https://example.net/a,b/c", "https://example.net/a,b/c"),
        ("https://example.net/x#a,b", "https://example.net/x#a,b"),
        ("(see https://example.net/x.)", "https://example.net/x"),
        ("(https://example.net/x?)", "https://example.net/x"),
    ],
)
def test_a_comma_or_a_parenthesis_stays_in_the_path_query_or_fragment(
    client: TestClient, written: str, url: str
) -> None:
    """0.6.0 cut each of these at the first comma or parenthesis. A trailing comma and an
    unbalanced parenthesis are still trimmed off, so a URL in a sentence comes back clean."""
    assert _urls(client, written) == [url]


@pytest.mark.parametrize(
    ("written", "urls"),
    [
        ("(see https://example.net/x)", ["https://example.net/x"]),
        ("https://example.net/x)", ["https://example.net/x"]),
        ("[https://example.net/x]", ["https://example.net/x"]),
        ("https://example.net/x, and", ["https://example.net/x"]),
        ("https://example.net/x),", ["https://example.net/x"]),
        (
            "<https://example.net/x>,<mailto:a@example.net>",
            ["https://example.net/x", "mailto:a@example.net"],
        ),
        (
            "https://a.example.net/x, https://b.example.net/y",
            ["https://a.example.net/x", "https://b.example.net/y"],
        ),
        # A comma directly before another `scheme://` ends the URL.
        (
            "https://a.example.net/x,https://b.example.net/y",
            ["https://a.example.net/x", "https://b.example.net/y"],
        ),
        # Without an authority, a comma ends the URL as it did: RFC 6068 separates the
        # recipients of `mailto:` with it, and `data:` keeps its payload out.
        ("mailto:a@example.net,b@example.net", ["mailto:a@example.net"]),
        ("data:text/plain;base64,QUJD", ["data:text/plain;base64"]),
    ],
)
def test_what_a_sentence_puts_around_a_url_is_still_left_out(
    client: TestClient, written: str, urls: list[str]
) -> None:
    """The control: punctuation around a URL, and a comma where it separates."""
    assert _urls(client, written) == urls


@pytest.mark.parametrize(
    ("written", "url"),
    [
        (
            "https://example.net/x,mailto:u@example.net",
            "https://example.net/x,mailto:u@example.net",
        ),
        ("https://example.net/x,b@c.example.org", "https://example.net/x,b@c.example.org"),
        ("a.example.net/x,b.example.org", "a.example.net/x,b.example.org"),
    ],
)
def test_what_a_comma_in_a_path_costs(client: TestClient, written: str, url: str) -> None:
    """Recorded, not wanted: a list joined with a comma and no space after a URL with a path is
    one path to RFC 3986, so the second item is read as part of the first."""
    assert _urls(client, written) == [url]


def test_a_footnote_after_a_url_is_not_part_of_it(client: TestClient) -> None:
    """`[` and `]` end a URL anywhere but around an IP-literal host. 0.6.0 returned
    `http//www.example.org[1`, the colon lost and the domain with it."""
    body = dissect(client, (REGRESSIONS / "2026-10-06-a-footnote-after-a-url.eml").read_bytes())
    found = [(o["type"], o["value"]) for o in body["messages"][0]["observables"]]
    assert [value for kind, value in found if kind == "url"] == [
        "http://www.example.org",
        "mailto:help@example.org",
        "http://192.0.2.10",
    ]
    assert {("domain", "www.example.org"), ("email", "help@example.org")} <= set(found)
    assert ("ip", "192.0.2.10") in found
    assert _urls(client, "https://example.net/path[2].") == ["https://example.net/path"]
    assert _urls(client, "https://example.net/a[b]c") == ["https://example.net/a"]


@pytest.mark.parametrize(
    ("written", "url"),
    [
        ("http://[2001:db8::1]/x", "http://[2001:db8::1]/x"),
        ("http://[2001:db8::1]:8080/x,y", "http://[2001:db8::1]:8080/x,y"),
        ("http://u@[2001:db8::1]/", "http://u@[2001:db8::1]/"),
    ],
)
def test_an_ipv6_literal_keeps_its_brackets_and_gives_its_address(
    client: TestClient, written: str, url: str
) -> None:
    """0.6.0 returned `http//[2001:db8::1` and no address."""
    found = _found(client, written)
    assert [value for kind, value in found if kind == "url"] == [url]
    assert ("ip", "2001:db8::1") in found


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        (
            "**http://a.example.net**",
            [("url", "http://a.example.net"), ("domain", "a.example.net")],
        ),
        ("|www.a.example.net|", [("url", "www.a.example.net"), ("domain", "www.a.example.net")]),
        (
            "http://a.example.net;b.example.org/x",
            [
                ("url", "http://a.example.net"),
                ("domain", "a.example.net"),
                ("url", "b.example.org/x"),
                ("domain", "b.example.org"),
            ],
        ),
        (
            "http://a.example.net:80;x",
            [("url", "http://a.example.net:80"), ("domain", "a.example.net")],
        ),
        # Left as it is: `*` is legal in a path, and trimming it would change URLs that end in
        # one. And with no host after `//`, the URL is read as before, from the first `/`.
        (
            "**http://a.example.net/x**",
            [("url", "http://a.example.net/x**"), ("domain", "a.example.net")],
        ),
        ("http://**a.example.net", [("url", "http://**a.example.net")]),
    ],
)
def test_a_host_in_text_is_labels_or_an_ip_literal(
    client: TestClient, written: str, expected: list[tuple[str, str]]
) -> None:
    """`[D32]`: 0.6.0 read `**http://a.example.net**` as the URL `http://a.example.net**`, with
    no domain, and `http://a.example.net;b.example.org/x` as one URL."""
    assert _found(client, written) == expected


def test_an_ipv4_address_written_otherwise_in_a_host_is_not_derived(client: TestClient) -> None:
    """The boundary of `ip`, written down (§11.2): dotted decimal. `3221225994` is 192.0.2.10
    to a browser, and the URL comes back without an `ip`."""
    assert _found(client, "http://3221225994/") == [("url", "http://3221225994/")]
