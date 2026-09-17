"""Taking the message in: SPEC §4 and §15. Cases 17, 20, 29, 30, 46."""

from __future__ import annotations

import hashlib

from conftest import SIMPLE, dissect
from fastapi.testclient import TestClient

from mail_dissect.settings import Settings


def test_both_channels_give_identical_results(client: TestClient) -> None:
    """Test 20: the two input forms are equal, so the same bytes give the same answer."""
    raw = dissect(client, SIMPLE)
    form = client.post("/v1/dissect", files={"eml": ("m.eml", SIMPLE, "message/rfc822")})
    assert form.status_code == 200
    through_form = form.json()

    for field in ("source", "messages", "tools", "flags"):
        assert through_form[field] == raw[field], field
    # Only what the contract excludes from determinism may differ (SPEC §17).
    assert through_form["dissect_id"] != raw["dissect_id"]


def test_large_field_survives_the_form_channel(client: TestClient) -> None:
    """R6: the framework caps a non-file field at 1 MB and text-decodes it (F11).

    Reading the form ourselves is what keeps the channels byte-identical, so the test uses a
    message well past that cap and compares hashes rather than status codes.
    """
    big = b"From: a@example.com\r\nSubject: big\r\n\r\n" + b"x" * (3 * 1024 * 1024)
    form = client.post("/v1/dissect", files={"eml": ("m.eml", big, "message/rfc822")})
    assert form.status_code == 200
    assert form.json()["source"]["sha256"] == hashlib.sha256(big).hexdigest()


def test_binary_file_is_unparsable(client: TestClient) -> None:
    """Test 29: a PDF sent as a message is refused, not dissected into nonsense."""
    response = client.post(
        "/v1/dissect",
        content=b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\nbinary",
        headers={"content-type": "message/rfc822"},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "UNPARSABLE"
    # SPEC §16: the envelope carries the identifier on failure too.
    assert body["dissect_id"]


def test_one_header_and_garbage_is_accepted(client: TestClient) -> None:
    """Test 30: the boundary is the presence of a header, not the quality of the rest."""
    body = dissect(client, b"X-Only: yes\r\n\r\n\x00\x01\x02 garbage \xff\xfe")
    assert body["ok"] is True
    assert body["messages"][0]["headers"] == {"x-only": ["yes"]}


def test_mbox_envelope_line_does_not_hide_the_headers(client: TestClient) -> None:
    """F1b: `From ` is an mbox envelope line to the stdlib, so the gate reads raw bytes."""
    body = dissect(client, b"From a@b Mon Jan 1 00:00:00 2026\r\nFrom: a@example.com\r\n\r\nx")
    assert "from" in body["messages"][0]["headers"]


def test_a_lone_from_with_a_space_is_not_a_message(client: TestClient) -> None:
    """F1b, the other half: `From : x` is not a header line, and nothing else is either."""
    response = client.post(
        "/v1/dissect",
        content=b"From : a@example.com\r\n\r\nbody",
        headers={"content-type": "message/rfc822"},
    )
    assert response.status_code == 422


def test_message_over_the_input_limit(settings: Settings, clock: object) -> None:
    """Test 17: TOO_LARGE at 413, refused before parsing — not `truncated`."""
    from fastapi.testclient import TestClient as Client

    from mail_dissect.app import create_app

    small = settings.model_copy(update={"max_message_bytes": 512})
    with Client(create_app(small, clock=clock)) as client:  # type: ignore[arg-type]
        response = client.post(
            "/v1/dissect",
            content=b"From: a@example.com\r\n\r\n" + b"x" * 1024,
            headers={"content-type": "message/rfc822"},
        )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "TOO_LARGE"


def test_empty_body_is_a_bad_request(client: TestClient) -> None:
    response = client.post("/v1/dissect", content=b"", headers={"content-type": "message/rfc822"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "BAD_REQUEST"


def test_headers_are_complete_and_ordered(client: TestClient) -> None:
    """Test 46: a custom header and a repeated one, both present, values in order."""
    raw = (
        b"From: a@example.com\r\n"
        b"Received: from one\r\n"
        b"X-Custom: first\r\n"
        b"Received: from two\r\n"
        b"Subject: =?utf-8?q?caf=C3=A9?=\r\n"
        b"\r\nbody"
    )
    headers = dissect(client, raw)["messages"][0]["headers"]
    assert headers["received"] == ["from one", "from two"]
    assert headers["x-custom"] == ["first"]
    assert headers["subject"] == ["café"]  # RFC 2047 decoded through the registry (F7)
    assert set(headers) == {"from", "received", "x-custom", "subject"}


def test_source_hashes_are_of_the_message_bytes(client: TestClient) -> None:
    body = dissect(client, SIMPLE)
    assert body["source"]["size"] == len(SIMPLE)
    assert body["source"]["md5"] == hashlib.md5(SIMPLE, usedforsecurity=False).hexdigest()
    assert body["source"]["sha1"] == hashlib.sha1(SIMPLE, usedforsecurity=False).hexdigest()
    assert body["source"]["sha256"] == hashlib.sha256(SIMPLE).hexdigest()
