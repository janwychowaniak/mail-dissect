"""The MIME core: SPEC §6, §7, §13.2.

Acceptance cases 1-4, 8-11, 15, 16, 37, 39, 43-48, 51, 57, 63-65.
"""

from __future__ import annotations

import hashlib
import time

import builders as b
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.settings import Settings


def _part(body: dict, index: int) -> dict:
    return body["messages"][0]["mime_parts"][index]


def test_simple_single_part(client: TestClient) -> None:
    """Test 1."""
    body = dissect(client, b.simple_text("hello world"))
    message = body["messages"][0]
    assert len(body["messages"]) == 1
    assert message["depth"] == 0
    assert [part["content_type"] for part in message["mime_parts"]] == ["text/plain"]
    assert message["body"]["text"] == "hello world"
    assert message["body"]["text_part_index"] == 0
    assert message["body"]["html"] is None and message["body"]["html_artifact_id"] is None
    assert message["attachments"] == []


def test_alternative_with_html_and_text(client: TestClient) -> None:
    """Test 2: both representations, both reported, neither chosen over the other."""
    raw = b.multipart(
        "alternative",
        b.part("text/plain", b"plain version"),
        b.part("text/html", b"<p>html version</p>"),
    )
    message = dissect(client, raw)["messages"][0]
    assert message["body"]["text"] == "plain version"
    assert message["body"]["html"] == "<p>html version</p>"
    assert message["body"]["text_part_index"] == 1
    assert message["body"]["html_part_index"] == 2
    assert message["attachments"] == []  # a body part is not an attachment


def test_nested_message_is_the_original(client: TestClient) -> None:
    """Test 3: `messages[]` carries the nested message, not the envelope around it."""
    inner = b.message({"From": "inner@example.com", "Subject": "forwarded"}, body=b"inner body")
    raw = b.multipart("mixed", b.part("text/plain", b"see attached"), b.nested(inner))
    body = dissect(client, raw)

    assert [m["depth"] for m in body["messages"]] == [0, 1]
    nested = body["messages"][1]
    assert nested["headers"]["from"] == ["inner@example.com"]
    assert nested["body"]["text"] == "inner body"
    # It is also an attachment of its parent: a part, not a container, not the body (§6.3).
    assert body["messages"][0]["attachments"][0]["declared_mime"] == "message/rfc822"


def test_two_nestings_and_a_two_level_nesting(client: TestClient) -> None:
    """Test 4: depth-first, because a nested message lives inside the one before it."""
    deep = b.message({"From": "deep@example.com"}, body=b"deep")
    middle = b.multipart("mixed", b.part("text/plain", b"middle"), b.nested(deep), boundary="IN")
    sibling = b.message({"From": "sibling@example.com"}, body=b"sibling")
    raw = b.multipart("mixed", b.nested(middle), b.nested(sibling), boundary="BB")

    body = dissect(client, raw)
    assert [m["depth"] for m in body["messages"]] == [0, 1, 2, 1]
    assert body["messages"][2]["headers"]["from"] == ["deep@example.com"]
    assert body["messages"][3]["headers"]["from"] == ["sibling@example.com"]


def test_nested_original_is_byte_identical(client: TestClient) -> None:
    """Test 63 `[D12]`: the artifact is the input's bytes, and the hash is of those bytes.

    An implementation that reassembles the message from its parsed parts passes every test
    of structure and fails this one — which is the only reason it exists.

    The inner message is deliberately NOT canonical: a header long enough to be refolded and
    one written without a space after its colon. A canonical message survives a rebuild
    byte-for-byte (F1), so a fixture made of one would pass against a reassembling
    implementation and prove nothing.
    """
    inner = b.message(
        raw_headers=(
            b"From:a@example.com\r\n"
            b"Subject: " + b"a very long subject that the generator will refold " * 3
        ),
        body=b"line one\r\nline two",
    )
    raw = b.multipart("mixed", b.part("text/plain", b"cover"), b.nested(inner))
    body = dissect(client, raw)

    artifact = next(a for a in body["artifacts"] if a["kind"] == "eml" and a["message_index"] == 1)
    fetched = client.get(f"/v1/artifact/{body['dissect_id']}/{artifact['artifact_id']}")
    assert fetched.content == inner
    assert artifact["sha256"] == hashlib.sha256(inner).hexdigest()
    # The parent's attachment entry hashes the same bytes.
    attachment = body["messages"][0]["attachments"][0]
    assert attachment["sha256"] == hashlib.sha256(inner).hexdigest()


def test_transport_encoded_nesting_is_still_a_message(client: TestClient) -> None:
    """Test 64 (F2): the standard library turns this into a bogus text part and says nothing."""
    inner = b.message({"From": "enc@example.com", "Subject": "encoded"}, body=b"encoded body")
    raw = b.multipart("mixed", b.nested(inner, encoding="base64"))
    body = dissect(client, raw)

    assert len(body["messages"]) == 2, "the nested message was not recognised as a message"
    assert body["messages"][1]["depth"] == 1
    assert body["messages"][1]["headers"]["from"] == ["enc@example.com"]
    artifact = next(a for a in body["artifacts"] if a["kind"] == "eml" and a["message_index"] == 1)
    fetched = client.get(f"/v1/artifact/{body['dissect_id']}/{artifact['artifact_id']}")
    assert fetched.content == inner, "the eml artifact must hold the decoded message"


def test_two_nestings_with_html_give_two_body_artifacts(client: TestClient) -> None:
    """Test 15: artifacts are attributable to their message, which is what `[D3]` rests on."""
    first = b.multipart("alternative", b.part("text/html", b"<p>one</p>"), boundary="N1")
    second = b.multipart("alternative", b.part("text/html", b"<p>two</p>"), boundary="N2")
    raw = b.multipart("mixed", b.nested(first), b.nested(second), boundary="BB")

    body = dissect(client, raw)
    html_artifacts = [a for a in body["artifacts"] if a["kind"] == "body_html"]
    assert len(html_artifacts) == 2
    assert sorted(a["message_index"] for a in html_artifacts) == [1, 2]
    assert body["messages"][1]["body"]["html"] == "<p>one</p>"
    assert body["messages"][2]["body"]["html"] == "<p>two</p>"


def test_mixed_with_two_text_parts(client: TestClient) -> None:
    """Test 37: the first is the body, the second is an attachment — one rule, no exception."""
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"the body"),
        b.part("text/plain", b"attached note", filename="note.txt"),
    )
    message = dissect(client, raw)["messages"][0]
    assert message["body"]["text"] == "the body"
    assert message["body"]["text_part_index"] == 1
    assert [a["part_index"] for a in message["attachments"]] == [2]


def test_two_attachments_with_the_same_name(client: TestClient) -> None:
    """Test 39: the filename is not an identifier; the index is (§5.2)."""
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body"),
        b.part("application/pdf", b"%PDF-1.4 first", filename="invoice.pdf"),
        b.part("application/pdf", b"%PDF-1.4 second", filename="invoice.pdf"),
    )
    attachments = dissect(client, raw)["messages"][0]["attachments"]
    assert [a["part_index"] for a in attachments] == [2, 3]
    assert {a["filename"] for a in attachments} == {"invoice.pdf"}
    assert attachments[0]["sha256"] != attachments[1]["sha256"]


def test_address_decomposition(client: TestClient) -> None:
    """Test 43: every address header, in full."""
    raw = b.message(
        [
            ("From", "=?utf-8?q?Jan_Wychowaniak?= <jan@example.com>"),
            ("To", 'first@example.com, "Second, Person" <second@example.org>'),
            ("Reply-To", "elsewhere@other.example"),
            ("Return-Path", "<bounce@example.net>"),
        ],
        body=b"body",
    )
    addresses = dissect(client, raw)["messages"][0]["addresses"]
    assert addresses["from"] == [
        {
            "display_name": "Jan Wychowaniak",
            "address": "jan@example.com",
            "local_part": "jan",
            "domain": "example.com",
        }
    ]
    assert [a["address"] for a in addresses["to"]] == ["first@example.com", "second@example.org"]
    assert addresses["to"][1]["display_name"] == "Second, Person"
    assert addresses["reply-to"][0]["domain"] == "other.example"
    # F6: not an address header in the standard library's registry until we remap it.
    assert addresses["return-path"][0]["address"] == "bounce@example.net"


def test_received_chain(client: TestClient) -> None:
    """Test 44: three hops in header order, nulls where the header was incomplete."""
    raw = b.message(
        [
            (
                "Received",
                "from a.example (a.example [192.0.2.1]) by b.example with ESMTP id X1 "
                "for <c@example.com>; Tue, 1 Sep 2026 10:00:00 +0000",
            ),
            ("Received", "by internal.example with LMTP id X2"),
            ("Received", "from [2001:db8::1] by edge.example; Tue, 1 Sep 2026 09:59:00 +0000"),
            ("From", "a@example.com"),
        ],
        body=b"body",
    )
    hops = dissect(client, raw)["messages"][0]["received"]
    assert len(hops) == 3
    assert hops[0]["from_host"] == "a.example" and hops[0]["from_ip"] == "192.0.2.1"
    assert hops[0]["with"] == "ESMTP" and hops[0]["id"] == "X1"
    assert hops[0]["for"] == "c@example.com"
    assert hops[1]["from_host"] is None and hops[1]["timestamp"] is None
    assert hops[2]["from_ip"] == "2001:db8::1" and hops[2]["from_host"] is None


def test_authentication_results_with_four_methods(client: TestClient) -> None:
    """Test 45: every method present, including one nobody standardised."""
    raw = b.message(
        [
            (
                "Authentication-Results",
                "mx.example.org; spf=pass smtp.mailfrom=example.com; "
                "dkim=fail header.d=example.com; dmarc=none; x-vendor-check=suspicious",
            ),
            ("From", "a@example.com"),
        ],
        body=b"body",
    )
    message = dissect(client, raw)["messages"][0]
    assert [entry["method"] for entry in message["auth"]] == [
        "spf",
        "dkim",
        "dmarc",
        "x-vendor-check",
    ]
    assert message["auth"][0]["params"] == {"smtp.mailfrom": "example.com"}
    # The raw header stays: decomposition never replaces it (§7).
    assert message["headers"]["authentication-results"]


def test_declared_type_differs_from_detected(client: TestClient) -> None:
    """Test 47: both values, and no comment from the service about which is 'real'."""
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body"),
        b.part("image/png", b"%PDF-1.4 actually a pdf", filename="picture.png"),
    )
    attachment = dissect(client, raw)["messages"][0]["attachments"][0]
    assert attachment["declared_mime"] == "image/png"
    assert attachment["detected_mime"] == "application/pdf"
    assert dissect(client, raw)["flags"] == []


def test_declared_charset_differs_from_used(client: TestClient) -> None:
    """Test 48: both values, the content readable, and the flag that says so."""
    raw = b.multipart("mixed", b.part("text/plain", "zażółć".encode("iso-8859-2"), charset="utf-8"))
    body = dissect(client, raw)
    part = _part(body, 1)
    assert part["charset_declared"] == "utf-8"
    assert part["charset_used"] == "cp1252"
    assert "encoding_fallback" in body["flags"]
    assert body["messages"][0]["body"]["text"]  # decoded, deterministically, not guessed


def test_encoded_headers_and_eight_bit_body(client: TestClient) -> None:
    """Test 8: RFC 2047 headers next to a body that lies about its encoding."""
    raw = b.message(
        [("From", "a@example.com"), ("Subject", "=?iso-8859-2?q?za=BF=F3=B3=E6?=")],
        body="zażółć".encode("iso-8859-2"),
    )
    body = dissect(client, raw)
    assert body["messages"][0]["headers"]["subject"] == ["zażółć"]
    assert body["messages"][0]["body"]["text"] is not None


def test_all_three_hashes_match_an_independent_computation(client: TestClient) -> None:
    """Tests 11 and 51: for the message and for every attachment."""
    payload = b"%PDF-1.4 " + bytes(range(256))
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body"),
        b.part("application/pdf", payload, encoding="base64", filename="a.pdf"),
    )
    body = dissect(client, raw)
    assert body["source"] == {
        "size": len(raw),
        "md5": hashlib.md5(raw, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    attachment = body["messages"][0]["attachments"][0]
    assert attachment["md5"] == hashlib.md5(payload, usedforsecurity=False).hexdigest()
    assert attachment["sha1"] == hashlib.sha1(payload, usedforsecurity=False).hexdigest()
    assert attachment["sha256"] == hashlib.sha256(payload).hexdigest()


def test_oversized_attachment(settings: Settings, clock: object) -> None:
    """Test 10: healthy material the service chose not to carry — hashes stay."""
    payload = b"x" * 5000
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body"),
        b.part("application/octet-stream", payload, filename="big.bin"),
    )
    small = settings.model_copy(update={"max_attachment_bytes": 100})
    with TestClient(create_app(small, clock=clock)) as client:  # type: ignore[arg-type]
        body = dissect(client, raw)

    attachment = body["messages"][0]["attachments"][0]
    assert "truncated" in body["flags"]
    assert attachment["artifact_id"] is None
    assert attachment["size"] == len(payload)
    assert attachment["sha256"] == hashlib.sha256(payload).hexdigest()
    # The rest of the dissection is complete.
    assert body["messages"][0]["body"]["text"] == "body"


def test_attachment_with_broken_encoding(client: TestClient) -> None:
    """Test 16: damage, not a limit — so hashes are null and the flag is a different one."""
    broken = (
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="x.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\nQUJDR"
    )
    raw = b.multipart("mixed", b.part("text/plain", b"body"), broken)
    body = dissect(client, raw)
    attachment = body["messages"][0]["attachments"][0]
    assert "attachment_unreadable" in body["flags"]
    assert "truncated" not in body["flags"], "damage must not read as a size limit (test 10)"
    assert attachment["artifact_id"] is None
    assert attachment["md5"] is None and attachment["sha256"] is None
    assert body["messages"][0]["body"]["text"] == "body"


def test_damaged_mime_is_normal_input(client: TestClient) -> None:
    """Test 9: a container whose boundary never closes is dissected, not refused."""
    raw = b.multipart(
        "mixed", b.part("text/plain", b"body"), b.part("text/plain", b"more"), close=False
    )
    body = dissect(client, raw)
    assert body["ok"] is True
    assert "malformed_mime" in body["flags"]
    assert body["messages"][0]["body"]["text"] == "body"
    assert len(body["messages"][0]["mime_parts"]) == 3  # dissected as far as it goes


def test_attachment_filename_is_sanitised_in_the_response_header(client: TestClient) -> None:
    """Test 57: a name with a path and control characters, served safely (§13.3)."""
    # Two text/html parts on purpose: the FIRST is the body by the one rule of §6.3, and
    # `Content-Disposition: attachment` does not change that. The second is the attachment
    # this test is about - and that pairing is itself the rule being exercised.
    raw = b.multipart(
        "mixed",
        b.part("text/html", b"<p>the body</p>"),
        b.part(
            "text/html",
            b"<script>alert(1)</script>",
            filename="../../etc/pa\tsswd.html",
            disposition="attachment",
        ),
    )
    body = dissect(client, raw)
    assert body["messages"][0]["body"]["html_part_index"] == 1
    attachment = body["messages"][0]["attachments"][0]
    assert attachment["part_index"] == 2
    response = client.get(f"/v1/artifact/{body['dissect_id']}/{attachment['artifact_id']}")

    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "/" not in disposition and "\t" not in disposition
    assert "text/html" not in response.headers.values()


def test_part_count_far_over_the_limit_is_cut_in_scan_time(
    settings: Settings, clock: object
) -> None:
    """Test 65 `[D13]`: the assertion is on the CLOCK, not only on the flag.

    A limit checked on a finished tree passes the content assertion and fails this one,
    which is the whole point: it protects against the size of the result, not the work.
    """
    # Sized so the two paths are far apart: cutting first is ~70x cheaper than building the
    # tree and discovering afterwards that it was too big. At 20 000 parts a full parse still
    # fits inside a second, and the assertion could not tell the two apart.
    raw = b.multipart("mixed", *[b.part("text/plain", b"x") for _ in range(100_000)])
    limited = settings.model_copy(update={"max_mime_parts": 50})
    with TestClient(create_app(limited, clock=clock)) as client:  # type: ignore[arg-type]
        started = time.perf_counter()
        body = dissect(client, raw)
        elapsed = time.perf_counter() - started

    assert "truncated" in body["flags"]
    assert len(body["messages"][0]["mime_parts"]) <= 50
    assert elapsed < 1.0, f"took {elapsed:.1f}s — the tree was built before the limit bit"


@pytest.mark.parametrize(
    ("depth_limit", "expected_messages", "cut"),
    [(1, 2, True), (2, 3, False)],
)
def test_nesting_deeper_than_the_limit_is_partial_not_an_error(
    settings: Settings, clock: object, depth_limit: int, expected_messages: int, cut: bool
) -> None:
    """SPEC §15: over a structural limit is `truncated`, never `TOO_LARGE`.

    The second case is the control: at a limit the message fits inside, nothing is cut and
    the flag must NOT appear — a flag that is always on says nothing.
    """
    deep = b.message({"From": "deep@example.com"}, body=b"deep")
    middle = b.multipart("mixed", b.nested(deep), boundary="IN")
    raw = b.multipart("mixed", b.nested(middle), boundary="BB")

    limited = settings.model_copy(update={"max_nesting_depth": depth_limit})
    with TestClient(create_app(limited, clock=clock)) as client:  # type: ignore[arg-type]
        body = dissect(client, raw)

    assert body["ok"] is True
    assert len(body["messages"]) == expected_messages
    assert ("truncated" in body["flags"]) is cut
