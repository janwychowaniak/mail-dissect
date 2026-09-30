"""An address written inside quotes: SPEC §7, `[D25]`. Acceptance case 70.

`From: "Bob Example <bob@example.net>"` is, by the grammar, one quoted local part with no
domain, and that is how the standard library reads it: an `address` holding the whole string,
brackets and all, and `domain: null`. An entry like that is read once more — its local part
goes through the same parser — and is taken only when that yields exactly one mailbox with a
domain and no defect. Anything less clean is left exactly as it was.
"""

from __future__ import annotations

import builders as b
import pins
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

from mail_dissect.headers import ADDRESS_HEADERS

BOB = {
    "display_name": "Bob Example",
    "address": "bob@example.net",
    "local_part": "bob",
    "domain": "example.net",
}


def _addresses(client: TestClient, header: str, value: str) -> list[dict]:
    raw = b.message([(header, value), ("Subject", "s")], body=b"body")
    return dissect(client, raw)["messages"][0]["addresses"][header.lower()]


@pytest.mark.parametrize("case", pins.QUOTED, ids=lambda case: case.file)
def test_a_saved_quoted_address(client: TestClient, case: pins.Quoted) -> None:
    """The seven reported shapes: three are read, three are left, and the control is not touched."""
    pins.check_quoted(case, lambda raw: dissect(client, raw))


@pytest.mark.parametrize("header", ADDRESS_HEADERS)
def test_every_address_header_is_read_the_same_way(client: TestClient, header: str) -> None:
    """Not `From` alone: choosing which headers deserve it would be a decision about them.

    The unquoted twin is the control — the same header on the same path, without the quotes —
    and the two must come out as the same entry.
    """
    assert _addresses(client, header, '"Bob Example <bob@example.net>"') == [BOB]
    assert _addresses(client, header, "Bob Example <bob@example.net>") == [BOB]


@pytest.mark.parametrize(
    ("value", "display_name", "address"),
    [
        ('"<bob@example.net>"', None, "bob@example.net"),
        ('" Bob Example <bob@example.net> "', "Bob Example", "bob@example.net"),
        (r'"\"Bob\" <bob@example.net>"', "Bob", "bob@example.net"),
        ('"Bob Example (desk) <bob@example.net>"', "Bob Example", "bob@example.net"),
        ('"=?utf-8?q?Z=C3=B3?= <bob@example.net>"', "Zó", "bob@example.net"),
        ('"Bob Example <bob@localhost>"', "Bob Example", "bob@localhost"),
        # A group is flattened here as it is at the top level of a header.
        ('"team: bob@example.net;"', None, "bob@example.net"),
        # Not one quoted string but a quoted word and an atom: the parser has already joined
        # them into one local part, and that local part reads as an address.
        ('"bob@example.net".x', None, "bob@example.net.x"),
    ],
    ids=[
        "no-name",
        "padded",
        "escaped-quotes",
        "comment",
        "encoded-word",
        "one-label-domain",
        "group",
        "quoted-word-and-atom",
    ],
)
def test_what_is_written_inside_the_quotes_is_read_as_an_address(
    client: TestClient, value: str, display_name: str | None, address: str
) -> None:
    """Whatever the parser accepts as one clean mailbox is taken, by the parser's own rules."""
    local_part, _, domain = address.rpartition("@")
    assert _addresses(client, "From", value) == [
        {
            "display_name": display_name,
            "address": address,
            "local_part": local_part,
            "domain": domain,
        }
    ]


@pytest.mark.parametrize(
    "local_part",
    [
        "bob@example.net, eve@example.org",  # two mailboxes, and no defect to object with
        "Bob <bob@>",  # a mailbox without a domain
        '"bob@example.net"',  # quoted twice: read once more, not until it gives in
        "bob",
    ],
    ids=["a-list", "no-domain-inside", "quoted-twice", "bare-word"],
)
def test_anything_less_than_one_clean_mailbox_is_left_alone(
    client: TestClient, local_part: str
) -> None:
    """`A clean reading or none`: the entry keeps the shape it had before `[D25]`."""
    written = local_part.replace("\\", "\\\\").replace('"', '\\"')
    value = local_part if local_part == "bob" else f'"{written}"'
    (entry,) = _addresses(client, "From", value)
    assert entry["domain"] is None
    assert entry["local_part"] == local_part
    assert entry["display_name"] is None


def test_the_display_name_is_never_where_an_address_comes_from(client: TestClient) -> None:
    """An entry that has a domain is what it says it is, whatever its display name looks like."""
    assert _addresses(client, "From", '"first@example.org" <second@example.net>') == [
        {
            "display_name": "first@example.org",
            "address": "second@example.net",
            "local_part": "second",
            "domain": "example.net",
        }
    ]
    assert _addresses(client, "From", '"Bob <first@example.org>" <second@example.net>') == [
        {
            "display_name": "Bob <first@example.org>",
            "address": "second@example.net",
            "local_part": "second",
            "domain": "example.net",
        }
    ]


def test_a_mailbox_with_no_domain_is_not_taken_even_without_a_defect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The parser never returns one without a defect (F19), so a stand-in has to.

    "Has a domain" is what the rule asks for. "No defect" happens to imply it on the
    interpreters measured, and an implication like that is the parser's to withdraw. The
    second stand-in is the control: the same reading with a domain is taken, so the refusal
    is about the domain and nothing else.
    """
    from email.headerregistry import Address

    from mail_dissect import headers

    def reading(address: Address) -> object:
        return type("Reading", (), {"addresses": (address,), "defects": ()})()

    monkeypatch.setattr(headers, "_registry", lambda name, value: reading(Address(username="bob")))
    assert headers._written_inside("from", "bob") is None

    clean = Address(username="bob", domain="example.net")
    monkeypatch.setattr(headers, "_registry", lambda name, value: reading(clean))
    assert headers._written_inside("from", "bob") is clean
