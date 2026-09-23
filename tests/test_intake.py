"""Taking the message in: SPEC §4 and §15. Cases 17, 20, 29, 30, 46."""

from __future__ import annotations

import hashlib

import pytest
from conftest import SIMPLE, dissect, mask_environment
from fastapi.testclient import TestClient

from mail_dissect.settings import Settings


def test_both_channels_give_identical_results(client: TestClient) -> None:
    """Test 20: the two input forms are equal, so the same bytes give the same answer."""
    raw = dissect(client, SIMPLE)
    form = client.post("/v1/dissect", files={"eml": ("m.eml", SIMPLE, "message/rfc822")})
    assert form.status_code == 200
    through_form = form.json()

    # Identical apart from what SPEC §17 excludes: the random identifiers, and nothing else.
    assert mask_environment(through_form) == mask_environment(raw)
    assert through_form["dissect_id"] != raw["dissect_id"]
    assert through_form["source"] == raw["source"]


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
    """Test 30: the boundary is the presence of a header, not the quality of the rest.

    Garbage *instead of* further headers is what makes this damaged rather than merely
    binary: the header block ends at the first line that is not one, and the parser says so.
    A message with one header and a binary body is not damaged at all, and the control below
    keeps the flag from becoming decoration.
    """
    body = dissect(client, b"X-Only: yes\r\nthis is not a header at all\r\n\r\nbody")
    assert body["ok"] is True
    assert body["messages"][0]["headers"] == {"x-only": ["yes"]}
    assert "malformed_mime" in body["flags"]


def test_a_binary_body_is_not_damage(client: TestClient) -> None:
    """The control for test 30: nothing about this message is malformed."""
    body = dissect(client, b"X-Only: yes\r\n\r\n\x00\x01\x02 binary \xff\xfe")
    assert body["ok"] is True
    assert body["flags"] == []


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


def test_an_eight_bit_header_byte_is_replaced_and_reported(client: TestClient) -> None:
    """[D20], F7: one byte above 0x7F in a header is a substitution, and it is said out loud.

    Until F17 this was a 500 for any header at all: compat32 handed the value out as an
    `email.header.Header`, which nothing downstream expects. The ASCII twin is the control -
    the same message on the same path, differing in the one byte - so the flag is raised by
    that byte and not by the shape of the message. The address is checked as well as the
    header, because the two are cleaned by different code and must not disagree.
    """
    twin = dissect(client, b"From: a@example.com\r\nTo: ev@x.example\r\nSubject: cafe\r\n\r\nb")
    assert twin["messages"][0]["headers"]["subject"] == ["cafe"]
    assert twin["flags"] == []

    body = dissect(
        client, b"From: a@example.com\r\nTo: \xe9v@x.example\r\nSubject: caf\xe9\r\n\r\nb"
    )
    message = body["messages"][0]
    assert message["headers"]["subject"] == ["caf\ufffd"]
    assert message["headers"]["to"] == ["\ufffdv@x.example"]
    assert message["addresses"]["to"][0]["address"] == "\ufffdv@x.example"
    assert body["flags"] == ["encoding_fallback"]


@pytest.mark.parametrize(
    ("header", "expected", "flags"),
    [
        # Raw UTF-8 (RFC 6532) reads without loss, so nothing was substituted.
        ("Subject: café".encode(), "café", []),
        # A broken encoded-word is the other way to a U+FFFD, and F7 promised the flag for it.
        (b"Subject: =?utf-8?q?caf=E9?=", "caf\ufffd", ["encoding_fallback"]),
        (b"Subject: =?utf-8?q?caf=C3=A9?=", "café", []),
        # A charset nobody can look up is a declaration that was not taken (SPEC §5.1).
        (b"Subject: =?x-no-such-charset?q?cafe?=", None, ["encoding_fallback"]),
        # A U+FFFD the sender wrote is material, not a substitution.
        ("Subject: caf\ufffd".encode(), "caf\ufffd", []),
    ],
)
def test_a_header_is_flagged_only_when_reading_it_fell_back(
    client: TestClient, header: bytes, expected: str | None, flags: list[str]
) -> None:
    """SPEC §5.1: `encoding_fallback` fires when, and only when, reading fell back."""
    body = dissect(client, b"From: a@example.com\r\n" + header + b"\r\n\r\nb")
    if expected is not None:
        assert body["messages"][0]["headers"]["subject"] == [expected]
    assert body["flags"] == flags


def test_raw_utf8_in_an_address_is_read_without_loss(client: TestClient) -> None:
    """[D20] as amended: a scrub that loses nothing is not reported.

    The address is cleaned by the scrub, not by the header registry, so this is the case the
    amendment is about; the 8-bit twin in the test above still raises the flag.
    """
    body = dissect(client, "From: a@example.com\r\nTo: Zoë <zoë@x.example>\r\n\r\nb".encode())
    message = body["messages"][0]
    assert message["headers"]["to"] == ["Zoë <zoë@x.example>"]
    assert message["addresses"]["to"][0]["display_name"] == "Zoë"
    assert message["addresses"]["to"][0]["address"] == "zoë@x.example"
    assert body["flags"] == []


@pytest.mark.parametrize(
    ("byte", "shown", "flags"),
    [
        (b"e", "cafe", []),  # the control
        (b"\xe9", "caf\ufffd", ["encoding_fallback"]),
        ("é".encode(), "café", []),
    ],
    ids=["ascii", "8-bit", "utf-8"],
)
def test_a_non_ascii_byte_in_a_part_header_is_read_and_served(
    client: TestClient, byte: bytes, shown: str, flags: list[str]
) -> None:
    """[D20], F17: the part's fields are read out of headers too, and served back by name.

    `content_id` and the filename reached the JSON encoder unscrubbed, and the filename would
    have reached `Content-Disposition` when the attachment is fetched. Only the byte that does
    not decode is reported; UTF-8 reads without loss.
    """
    raw = (
        b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=BB\r\n\r\n"
        b"--BB\r\nContent-Type: text/plain\r\n\r\nbody\r\n--BB\r\n"
        b"Content-Type: application/octet-stream\r\nContent-ID: <caf" + byte + b"@x>\r\n"
        b'Content-Disposition: attachment; filename="caf' + byte + b'.bin"\r\n'
        b"\r\npayload\r\n--BB--\r\n"
    )
    body = dissect(client, raw)
    part = body["messages"][0]["mime_parts"][2]
    assert part["content_id"] == f"<{shown}@x>"
    assert part["filename"] == f"{shown}.bin"
    assert body["flags"] == flags
    attachment = next(a for a in body["artifacts"] if a["kind"] == "attachment")
    assert attachment["filename"] == f"{shown}.bin"
    fetched = client.get(f"/v1/artifact/{body['dissect_id']}/{attachment['artifact_id']}")
    assert fetched.status_code == 200
    assert fetched.content == b"payload"


@pytest.mark.parametrize(
    ("disposition", "expected", "flags"),
    [
        (b'filename="plain.txt"', "plain.txt", []),  # the control: nothing declared
        (b"filename*=utf-8''caf%C3%A9.txt", "café.txt", []),
        (b"filename*=utf-8''caf%E9.txt", "caf\ufffd.txt", ["encoding_fallback"]),
        (b"filename*=x-no-such-charset''cafe.txt", None, ["encoding_fallback"]),
        (b'filename="=?utf-8?q?caf=C3=A9.txt?="', "café.txt", []),
        (b'filename="=?utf-8?q?caf=E9.txt?="', "caf\ufffd.txt", ["encoding_fallback"]),
        (b'filename="=?x-no-such-charset?q?cafe.txt?="', None, ["encoding_fallback"]),
    ],
    ids=[
        "plain",
        "rfc2231-utf8",
        "rfc2231-bad-bytes",
        "rfc2231-unknown-charset",
        "rfc2047-utf8",
        "rfc2047-bad-bytes",
        "rfc2047-unknown-charset",
    ],
)
def test_a_filename_is_flagged_only_when_its_declaration_fails(
    client: TestClient, disposition: bytes, expected: str | None, flags: list[str]
) -> None:
    """SPEC §5.1: both ways of declaring a filename's charset, taken or not.

    The standard library takes neither failure aloud: an RFC 2231 charset it cannot look up is
    read as another one, and bytes that do not decode become U+FFFD, both without a defect.
    """
    raw = (
        b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=BB\r\n\r\n"
        b"--BB\r\nContent-Type: text/plain\r\n\r\nbody\r\n--BB\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; " + disposition + b"\r\n"
        b"\r\npayload\r\n--BB--\r\n"
    )
    body = dissect(client, raw)
    if expected is not None:
        assert body["messages"][0]["mime_parts"][2]["filename"] == expected
    assert body["flags"] == flags


def test_source_hashes_are_of_the_message_bytes(client: TestClient) -> None:
    body = dissect(client, SIMPLE)
    assert body["source"]["size"] == len(SIMPLE)
    assert body["source"]["md5"] == hashlib.md5(SIMPLE, usedforsecurity=False).hexdigest()
    assert body["source"]["sha1"] == hashlib.sha1(SIMPLE, usedforsecurity=False).hexdigest()
    assert body["source"]["sha256"] == hashlib.sha256(SIMPLE).hexdigest()
