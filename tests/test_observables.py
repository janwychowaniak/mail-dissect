"""Indicator candidates: SPEC §11.

Acceptance cases 22, 24, 25, 26, 27, 28, 32, 33, 34, 35, 56, 66.
"""

from __future__ import annotations

import time

import builders as b
from conftest import FakeClock, dissect
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.settings import Settings


def _observables(client: TestClient, body_text: str) -> list[dict]:
    """Candidates from a message whose headers carry none of their own.

    A `From:` header would put its address and domain at the head of every list, correctly
    and unhelpfully — headers are scanned first `[D9]`, and these tests are about the body.
    """
    raw = b.message({"Subject": "a plain subject"}, body=body_text.encode())
    return dissect(client, raw)["messages"][0]["observables"]


def _of_type(observables: list[dict], type_: str) -> list[dict]:
    return [o for o in observables if o["type"] == type_]


def _values(observables: list[dict], type_: str) -> list[str]:
    return [o["value"] for o in _of_type(observables, type_)]


def test_url_yields_its_host_as_well(client: TestClient) -> None:
    """Test 34: decompose, do not select — a consumer after domains should not have to parse."""
    found = _observables(client, "See bit.ly/xyz and www.example.com for details.")
    assert _values(found, "url") == ["bit.ly/xyz", "www.example.com"]
    assert _values(found, "domain") == ["bit.ly", "www.example.com"]


def test_email_yields_its_domain_as_well(client: TestClient) -> None:
    """Test 35: the same rule as for a URL's host; asymmetry would be accidental."""
    found = _observables(client, "Write to sales@example.org please.")
    assert _values(found, "email") == ["sales@example.org"]
    assert "example.org" in _values(found, "domain")


def test_private_addresses_are_not_filtered(client: TestClient) -> None:
    """Test 28: whether an internal address is interesting depends on who is asking."""
    found = _observables(client, "Hosts 10.0.0.5, 127.0.0.1, 8.8.8.8 and 2001:db8::1.")
    assert _values(found, "ip") == ["10.0.0.5", "127.0.0.1", "8.8.8.8", "2001:db8::1"]
    assert [o["subtype"] for o in _of_type(found, "ip")] == ["ipv4", "ipv4", "ipv4", "ipv6"]


def test_a_version_number_is_not_a_domain(client: TestClient) -> None:
    """Test 33: grammar alone would say yes; the registry is what refuses."""
    found = _observables(client, "Upgrade to wersja.1.2 today.")
    assert _values(found, "domain") == []


def test_ambiguous_filename_and_domain(client: TestClient) -> None:
    """Tests 26 and 32: `zip` and `md` are both public suffixes and file extensions."""
    found = _observables(client, "Attached: raport.zip and README.md and faktura.pdf.")

    ambiguous = {o["value"] for o in found if o["ambiguous"]}
    assert ambiguous == {"raport.zip", "readme.md", "README.md"}
    assert _values(found, "filename") == ["raport.zip", "README.md", "faktura.pdf"]
    assert _values(found, "domain") == ["raport.zip", "readme.md"]
    # Unambiguous on both sides: `pdf` is not a public suffix, `com` is not an extension.
    assert [o["ambiguous"] for o in found if o["value"] == "faktura.pdf"] == [False]

    # `example.com` is ambiguous too, and the specification's example said otherwise until
    # the registry was measured: mime-db lists `com` as the extension of
    # application/x-msdownload. The rule did not change - the world did not match the
    # example. A genuinely unambiguous domain needs a suffix that is not also an extension.
    # `.net` is one of the suffixes that is NOT also an extension; `.org` is, via
    # text/x-org, and `.com` is, via application/x-msdownload.
    unambiguous = _observables(client, "Our site example.net is up.")
    assert _values(unambiguous, "domain") == ["example.net"]
    assert _values(unambiguous, "filename") == []
    assert all(o["ambiguous"] is False for o in unambiguous)

    dos_executable = _observables(client, "Our site example.com is up.")
    assert _values(dos_executable, "domain") == ["example.com"]
    assert _values(dos_executable, "filename") == ["example.com"]
    assert all(o["ambiguous"] for o in dos_executable)


def test_canonical_value_next_to_the_original(client: TestClient) -> None:
    """Test 27: host lowercased and in punycode; path and query untouched."""
    found = _observables(client, "Go to HTTPS://Bücher.DE/Über/Pfad?Q=Ą now.")
    url = _of_type(found, "url")[0]
    assert url["value"] == "https://xn--bcher-kva.de/Über/Pfad?Q=Ą"
    assert url["value_raw"] == "HTTPS://Bücher.DE/Über/Pfad?Q=Ą"
    assert _values(found, "domain") == ["xn--bcher-kva.de"]


def test_defanged_address_is_re_armed_and_marked(client: TestClient) -> None:
    """Test 25: the difference comes from re-arming, not from normalisation."""
    found = _observables(client, "Do not visit hxxp://zly[.]host or a(at)b[.]com.")

    urls = _of_type(found, "url")
    assert len(urls) == 1
    assert urls[0]["value"] == "http://zly.host"
    assert urls[0]["value_raw"] == "hxxp://zly[.]host"
    assert urls[0]["defanged"] is True
    # The other half of the proof: `hxxp:` is a syntactically valid scheme, so a URL
    # alternative ahead of the defanged one does not fail to match - it matches and stops at
    # the first bracket. Asserting only that the re-armed candidate exists would pass while
    # a truncated `hxxp://zly[` sat beside it.
    assert not any("[" in o["value"] or o["value"].endswith("//zly") for o in found)

    email = _of_type(found, "email")[0]
    assert email["value"] == "a@b.com"
    assert email["defanged"] is True
    # A defanged form never sets `ambiguous`: that flag is for one collision only.
    assert all(o["ambiguous"] is False for o in found)


def test_the_same_address_five_times(client: TestClient) -> None:
    """Test 24 `[D14]`: one entry, five occurrences, and a list of PLACES."""
    # `.org`, not `.example`: the latter is reserved but absent from the ICANN section of
    # the public suffix list, so it yields no domain candidate at all [D21].
    text = " ".join(["https://repeat.org/a"] * 5)
    found = _observables(client, f"{text} and repeat.org again")
    urls = _of_type(found, "url")
    assert len(urls) == 1
    assert urls[0]["occurrences"] == 5
    assert urls[0]["sources"] == [
        {"kind": "body_text", "header_name": None, "header_index": None, "part_index": 0}
    ]
    domain = _of_type(found, "domain")[0]
    assert domain["occurrences"] == 6  # five from the URLs, one written on its own


def test_candidates_from_headers_name_their_place(client: TestClient) -> None:
    """Test 56: `header_name` says which, `header_index` says which one of them."""
    raw = b.message(
        [
            ("From", "sender@example.com"),
            ("X-Origin", "first https://one.example/a"),
            ("X-Origin", "second https://two.example/b"),
        ],
        body=b"body",
    )
    found = dissect(client, raw)["messages"][0]["observables"]
    by_value = {o["value"]: o for o in found}

    assert by_value["sender@example.com"]["sources"] == [
        {"kind": "header", "header_name": "from", "header_index": 0, "part_index": None}
    ]
    assert by_value["https://two.example/b"]["sources"] == [
        {"kind": "header", "header_name": "x-origin", "header_index": 1, "part_index": None}
    ]


def test_scan_order_is_headers_then_text_then_html(client: TestClient) -> None:
    """`[D9]`: the order the list is in, and the reason it does not move (test 62)."""
    raw = b.multipart(
        "alternative",
        b.part("text/plain", b"plain https://from-text.example/"),
        b.part("text/html", b'<a href="https://from-html.example/">x</a>'),
        headers={"From": "sender@example.com", "X-Head": "https://from-header.example/"},
    )
    found = dissect(client, raw)["messages"][0]["observables"]
    urls = [o["value"] for o in found if o["type"] == "url"]
    assert urls == [
        "https://from-header.example/",
        "https://from-text.example/",
        "https://from-html.example/",
    ]
    assert found[0]["sources"][0]["kind"] == "header"


def test_an_address_in_both_lists_is_one_observable(client: TestClient) -> None:
    """Test 22: `links[]` and `resources[]` add HTML context; `observables[]` is canonical."""
    address = "https://tracker.example/pixel.gif"
    raw = b.multipart(
        "mixed", b.part("text/html", f'<img src="{address}"><a href="{address}">x</a>'.encode())
    )
    message = dissect(client, raw)["messages"][0]
    assert len(message["links"]) == 1 and len(message["resources"]) == 1
    urls = [o for o in message["observables"] if o["type"] == "url"]
    assert len(urls) == 1
    assert urls[0]["occurrences"] == 2


def test_written_hashes_are_candidates(client: TestClient) -> None:
    """SPEC §11: a digest written in the content is a candidate; a computed one is not."""
    found = _observables(
        client,
        "md5 d41d8cd98f00b204e9800998ecf8427e sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709",
    )
    assert [o["subtype"] for o in _of_type(found, "hash")] == ["md5", "sha1"]


def test_attachment_filenames_do_not_become_candidates(client: TestClient) -> None:
    """SPEC §11.2: they are a fact in `attachments[]`, not something the message says."""
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"see attached"),
        b.part("application/pdf", b"%PDF-1.4", filename="secret-invoice.pdf"),
    )
    message = dissect(client, raw)["messages"][0]
    assert message["attachments"][0]["filename"] == "secret-invoice.pdf"
    assert all("secret-invoice" not in o["value"] for o in message["observables"])


def test_sentence_noise_is_accepted_deliberately(client: TestClient) -> None:
    """SPEC §11.3: there is no clean rule, and clever rules break quietly.

    `to` is a public suffix, so a missing space after a full stop produces a candidate. The
    consumer gets a candidate, not a verdict, and has the means to reject it.
    """
    found = _observables(client, "kliknij tutaj.To jest ważne")
    assert "tutaj.to" in _values(found, "domain")


def test_the_extension_supplement_changes_recognition(settings: Settings, clock: FakeClock) -> None:
    """Test 66 `[D22]`: the same string, with and without the deployment's supplement."""
    text = "Run payload.scr immediately"

    with TestClient(create_app(settings, clock=clock)) as client:
        assert _observables(client, text) == []

    supplemented = Settings(
        **{**settings.model_dump(), "extra_file_extensions": ["scr"]}, _env_file=None
    )
    with TestClient(create_app(supplemented, clock=clock)) as client:
        found = _observables(client, text)
    assert _values(found, "filename") == ["payload.scr"]
    assert found[0]["ambiguous"] is False  # `scr` is not a public suffix


def test_a_base64_heavy_body_does_not_blow_up_the_scan(client: TestClient) -> None:
    """The grammar must stay linear on long unbroken runs, which mail is full of.

    Any "run of characters, then a required marker" construction backtracks over the whole
    run at every position where the marker is absent. The defanged alternative was written
    that way once and took 154 seconds on 200 kB; the assertion is on the clock, because the
    output looks identical either way. A full performance guard follows in stage 6 - this one
    exists now, while the class of bug is fresh.
    """
    body = ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5" * 4_000).encode()
    raw = b.multipart("mixed", b.part("text/plain", body))

    started = time.perf_counter()
    found = dissect(client, raw)["messages"][0]["observables"]
    elapsed = time.perf_counter() - started

    assert found == []
    assert elapsed < 5.0, f"took {elapsed:.1f}s on {len(body) / 1000:.0f} kB of base64"
