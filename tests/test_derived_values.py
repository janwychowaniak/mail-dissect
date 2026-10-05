"""A value derived from another candidate is checked against its type: SPEC §11.2, `[D30]`.

A URL's host becomes a `domain` only when it is labels, and a `mailto:` address becomes an
`email` one recipient at a time, each only when it is one address. The URL itself is returned
as it was written in every case: only the derived value that is not of its type is not.
"""

from __future__ import annotations

import builders as b
import pytest
from conftest import dissect
from fastapi.testclient import TestClient


def _from_text(client: TestClient, text: str) -> list[tuple[str, str]]:
    raw = b.message({"Subject": "s"}, body=f"see {text} now".encode())
    return [(o["type"], o["value"]) for o in dissect(client, raw)["messages"][0]["observables"]]


def _from_href(client: TestClient, href: str) -> list[tuple[str, str]]:
    raw = b.message(
        {"Subject": "s", "Content-Type": "text/html"}, body=f'<a href="{href}">x</a>'.encode()
    )
    return [(o["type"], o["value"]) for o in dissect(client, raw)["messages"][0]["observables"]]


@pytest.mark.parametrize("mark", list(";&!$*+=(~%"))
def test_a_host_that_is_not_labels_gives_no_domain(client: TestClient, mark: str) -> None:
    """0.6.0 returned `a.example.net;b.example.org` as a `domain`, and the same with each of
    these characters, as text and as an attribute alike.

    In an attribute the attribute gives the URL's boundaries, so the URL is the whole of it and
    gives no domain. In text, since `[D32]`, the host ends at the character, so what comes back
    on either side is labels; either way no `domain` holds it. The control is the same URL
    without the character, which gives its domain.
    """
    url = f"http://a.example.net{mark}b.example.org/x"
    for found in (_from_text(client, url), _from_href(client, url)):
        assert [value for kind, value in found if kind == "domain" and mark in value] == []
    found = _from_href(client, url)
    assert ("url", url) in found
    assert [value for kind, value in found if kind == "domain"] == []
    assert ("domain", "a.example.net") in _from_href(client, "http://a.example.net/x")


def test_labels_in_any_script_and_an_underscore_are_labels(client: TestClient) -> None:
    assert ("domain", "xn--bcher-kva.de") in _from_href(client, "http://bücher.de/x")
    # F12: `idna` refuses an underscore, and mail is full of them.
    assert ("domain", "a_b.example.net") in _from_href(client, "http://a_b.example.net/x")


def test_a_host_that_is_a_public_suffix_and_nothing_more_is_still_a_domain(
    client: TestClient,
) -> None:
    """One label is labels: 0.6.0 gave `domain` for such a host, and so does this release."""
    assert ("domain", "com") in _from_href(client, "http://com/")


def test_a_percent_encoded_host_gives_no_domain(client: TestClient) -> None:
    """Left as it is: no decoding is added, so the host is not labels as written."""
    found = _from_href(client, "https://exa%6Dple.net/")
    assert found == [("url", "https://exa%6Dple.net/")]


def test_a_mailto_list_gives_each_recipient_that_is_one_address(client: TestClient) -> None:
    """RFC 6068: recipients are separated by commas. 0.6.0 returned the whole list as one
    `email`, `a@example.net,b@example.org`."""
    assert _from_href(client, "mailto:a@example.net,b@example.org") == [
        ("url", "mailto:a@example.net,b@example.org"),
        ("email", "a@example.net"),
        ("domain", "example.net"),
        ("email", "b@example.org"),
        ("domain", "example.org"),
    ]
    assert ("email", "b@example.org") in _from_href(client, "mailto:a@example.net,,b@example.org")
    # A recipient that is not one address gives nothing, and nothing derived from it either.
    assert _from_href(client, "mailto:Jan%20K%20%3Cjan@example.net%3E") == [
        ("url", "mailto:Jan%20K%20%3Cjan@example.net%3E")
    ]
    assert [v for k, v in _from_href(client, "mailto:a@example.net,mailto:b@example.net")] == [
        "mailto:a@example.net,mailto:b@example.net",
        "a@example.net",
        "example.net",
    ]


def test_a_period_at_the_end_of_a_recipient_s_domain_is_read_as_in_a_host(
    client: TestClient,
) -> None:
    assert ("email", "u@example.net") in _from_href(client, "mailto:u@example.net.")
