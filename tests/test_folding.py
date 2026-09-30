"""Folded headers, and what `headers{}` is a view of: SPEC §7, `[D24]`, F18.

Acceptance cases 67-69. A header may be written across several lines, and where its writer
broke it is not part of its value (RFC 5322 §2.2.3). Until 0.3.0 the line break stayed in the
value: an address header with one came back as nulls, and a word cut between two encoded-words
came back as two.

Every saved message here was red before the fix, and its unfolded twin is the control: the
same header on the same path, differing in the line break alone.
"""

from __future__ import annotations

import re
from pathlib import Path

import builders as b
import pins
import pytest
from conftest import dissect
from fastapi.testclient import TestClient

SPEC = Path(__file__).parent.parent / "docs" / "SPEC.md"


def _saved(name: str) -> bytes:
    return (pins.REGRESSIONS / name).read_bytes()


@pytest.mark.parametrize("case", pins.FOLDED, ids=lambda case: case.file)
def test_a_folded_header_yields_its_value(client: TestClient, case: pins.Folded) -> None:
    """Case 68: the address is decomposed and the words are joined, fold or no fold."""
    pins.check_values(case, lambda raw: dissect(client, raw))


@pytest.mark.parametrize("case", pins.FOLDED, ids=lambda case: case.file)
def test_a_saved_folded_message_equals_its_unfolded_twin(
    client: TestClient, case: pins.Folded
) -> None:
    """Case 67, on the reported shapes: the twin differs in the line breaks and nothing else."""
    pins.check_twin(case, lambda raw: dissect(client, raw))


_HEADER_LINE = re.compile(rb"^[A-Za-z][A-Za-z0-9-]*:")


def _fold_everywhere(raw: bytes, line_break: bytes) -> bytes:
    """Break every header line before each space and tab it has, at every level.

    The most folded a message can be: after the colon, inside a quoted name, between two
    encoded-words, in the headers of a part and of a nested message alike.
    """
    lines = []
    for line in raw.split(b"\r\n"):
        if _HEADER_LINE.match(line):
            line = re.sub(rb"[ \t]", lambda space: line_break + space.group(0), line)
        lines.append(line)
    return b"\r\n".join(lines)


def _unfolded_messages() -> dict[str, bytes]:
    """One of every place a header is read from, written on one line each."""
    inner = b.message(
        [
            ("From", "=?utf-8?q?Inner_Sender?= <inner@example.net>"),
            ("To", 'first@example.org, "Second, Person" <second@example.org>'),
            ("Subject", "=?utf-8?B?c2VlIGV4YW0=?= =?utf-8?B?cGxlLm5ldCBub3c=?="),
        ],
        body=b"inner body",
    )
    return {
        "addresses": b.message(
            [
                ("From", "=?iso-8859-2?Q?=A3=F3d=BC_Testowy?= <sender@example.net>"),
                ("To", 'first@example.org, "Second, Person" <second@example.org>'),
                ("Cc", "Third Person <third@example.org>"),
                ("Reply-To", "elsewhere@other.example"),
                ("Sender", "Desk <desk@example.net>"),
                ("Return-Path", "<bounce@example.net>"),
                ("Subject", "plain words in a subject"),
            ],
            body=b"body",
        ),
        "trace": b.message(
            [
                (
                    "Received",
                    "from a.example (a.example [192.0.2.1]) by b.example with ESMTP id X1 "
                    "for <c@example.com>; Tue, 1 Sep 2026 10:00:00 +0000",
                ),
                (
                    "Authentication-Results",
                    "mx.example.org; spf=pass (sender is 192.0.2.1) smtp.mailfrom=example.com; "
                    "dkim=fail header.d=example.com; dmarc=none",
                ),
                ("List-Unsubscribe", "<https://lists.example.net/u?id=1>, <mailto:u@example.net>"),
                ("Message-ID", "<one@example.net>"),
                ("References", "<zero@example.net> <half@example.net>"),
                ("Date", "Tue, 1 Sep 2026 10:00:00 +0000"),
                ("From", "a@example.com"),
                ("Subject", "=?utf-8?B?c2VlIGV4YW0=?= =?utf-8?B?cGxlLm5ldCBub3c=?="),
                ("X-Note", "10.0.0.5 and raport.zip and https://header.example/one"),
            ],
            body=b"body",
        ),
        "parts": b.multipart(
            "mixed",
            b.part("text/plain", b"cover", charset="utf-8"),
            b.part(
                "application/pdf",
                b"%PDF-1.4 data",
                encoding="base64",
                filename="quarterly report.pdf",
                content_id="<part one@example.net>",
            ),
            b.nested(inner),
            headers={"From": "Outer Sender <outer@example.org>", "Subject": "outer subject"},
        ),
    }


@pytest.mark.parametrize("line_break", [b"\r\n", b"\n"], ids=["crlf", "bare-lf"])
@pytest.mark.parametrize("name", sorted(_unfolded_messages()))
def test_folding_does_not_change_the_result(
    client: TestClient, name: str, line_break: bytes
) -> None:
    """Case 67, as a property: fold a message as far as it will go and nothing moves.

    Every header line at every level — the message's, a part's, a nested message's — broken
    before each space and tab. The round trip is asserted first, because a fold that changed
    the text, or one that never landed, would make the comparison mean something else.
    """
    raw = _unfolded_messages()[name]
    folded = _fold_everywhere(raw, line_break)
    restored, folds = pins.unfolded(folded)
    assert restored == raw and folds > 5, "the fixture is not a pure fold of the original"

    assert pins.comparable(dissect(client, folded)) == pins.comparable(dissect(client, raw))


def test_received_is_decomposed_the_same_folded_or_not(client: TestClient) -> None:
    """A hop folded BETWEEN its fields was already right; this is what keeps it so.

    Not a statement about every fold: one inside the timestamp did reach the hop, and has a
    test of its own below.
    """
    message = dissect(client, _saved("2026-09-30-folded-received.eml"))["messages"][0]
    assert message["received"] == [
        {
            "from_host": "mx.example.net",
            "from_ip": "192.0.2.10",
            "by_host": "mail.example.org",
            "with": "ESMTPS",
            "id": "abc123",
            "for": "recipient@example.org",
            "timestamp": "Tue, 30 Sep 2026 10:00:00 +0200",
        }
    ]


def test_authentication_results_are_decomposed_the_same_folded_or_not(
    client: TestClient,
) -> None:
    """`auth[]` folded BETWEEN its methods was already right; this is what keeps it so."""
    message = dissect(client, _saved("2026-09-30-folded-authentication-results.eml"))["messages"][0]
    assert message["auth"] == [
        {"method": "spf", "result": "pass", "params": {"smtp.mailfrom": "example.net"}},
        {"method": "dkim", "result": "fail", "params": {"header.d": "example.net"}},
        {
            "method": "dmarc",
            "result": "pass",
            "params": {"action": "none", "header.from": "example.net"},
        },
    ]


def test_a_fold_inside_a_decomposed_value_is_not_in_the_field(client: TestClient) -> None:
    """`received[].timestamp` and a quoted `auth[]` parameter take more than one token.

    Every other decomposed field is a single token, which white space ends, so a fold could
    only ever fall between them. These two carried the line break into the field - and the
    first draft of this release said `received[]` and `auth[]` did not change, on the
    strength of a fixture folded between fields only.
    """
    message = dissect(client, _saved("2026-09-30-folded-inside-a-timestamp-and-a-parameter.eml"))[
        "messages"
    ][0]
    assert [hop["timestamp"] for hop in message["received"]] == [
        "Wed, 30 Sep 2026 10:00:00 +0200\t(CEST)",
        "Wed, 30 Sep 2026 09:59:58 +0200",
    ]
    assert message["auth"] == [
        {
            "method": "dkim",
            "result": "fail",
            "params": {"reason": "bad signature", "header.d": "example.net"},
        }
    ]


def test_a_word_cut_by_a_fold_is_one_candidate(client: TestClient) -> None:
    """A domain split between two encoded-words is that domain, not its second half.

    The fold used to stay between the halves, so the scan found `ple.com` — a candidate for a
    host the message never names — and lost `example.com`.
    """
    message = dissect(client, _saved("2026-09-30-folded-subject-splits-a-domain.eml"))["messages"][
        0
    ]
    from_subject = [
        (o["type"], o["value"])
        for o in message["observables"]
        if any(s["kind"] == "header" and s["header_name"] == "subject" for s in o["sources"])
    ]
    assert from_subject == [("domain", "example.com"), ("filename", "example.com")]


def test_a_folded_content_type_keeps_its_parameters(client: TestClient) -> None:
    """`headers.content-type` ended at the semicolon; the tree was right all along."""
    message = dissect(client, _saved("2026-09-30-folded-content-type.eml"))["messages"][0]
    assert message["headers"]["content-type"] == ['text/plain; charset="iso-8859-2"']
    # The control: the part was always read correctly, so the charset reached the body.
    assert message["mime_parts"][0]["charset_declared"] == "iso-8859-2"
    assert message["body"]["text"] == "Zażółć gęślą jaźń\r\n"


@pytest.mark.parametrize(
    ("headers", "field", "value"),
    [
        (
            b"Content-Type: application/octet-stream\r\n"
            b'Content-Disposition: attachment; filename="long name{} part.bin"',
            "filename",
            "long name part.bin",
        ),
        (b'Content-Type: application/octet-stream; name="a{}\tb.bin"', "filename", "a\tb.bin"),
        (
            b"Content-Type: application/octet-stream\r\nContent-ID: <part{} one@example.net>",
            "content_id",
            "<part one@example.net>",
        ),
    ],
    ids=["filename", "name", "content-id"],
)
def test_a_fold_inside_a_part_header_is_not_in_the_field(
    client: TestClient, headers: bytes, field: str, value: str
) -> None:
    """A part's fields are read out of headers too, and carried the line break with them.

    The first round is the control: the same header on one line, which was always right.
    """
    for line_break in (b"", b"\r\n"):
        raw = b.multipart(
            "mixed",
            b.part("text/plain", b"body"),
            headers.replace(b"{}", line_break) + b"\r\n\r\npayload",
        )
        part = dissect(client, raw)["messages"][0]["mime_parts"][2]
        assert part[field] == value, f"with {line_break!r}"


def test_a_folded_address_header_reports_what_its_unfolded_twin_reports(
    client: TestClient,
) -> None:
    """`encoding_fallback` follows the value, so it no longer depends on the line break.

    The header registry refuses an address with a line break in it, so the folded header used
    to come back undecoded, with nothing substituted and nothing to report — while the same
    header on one line was decoded, got its U+FFFD and raised the flag.
    """
    for line_break in (b"", b"\r\n"):
        raw = b"From: =?utf-8?q?caf=E9?=" + line_break + b" <a@example.net>\r\nSubject: s\r\n\r\nb"
        body = dissect(client, raw)
        assert body["messages"][0]["headers"]["from"] == ["caf\ufffd <a@example.net>"]
        assert body["flags"] == ["encoding_fallback"], f"with {line_break!r}"


def test_headers_are_the_parsed_view_and_the_artifact_is_the_record(client: TestClient) -> None:
    """Case 69 `[D24]`: what differs between `headers{}` and what was written, and where.

    A structured header comes back as the parser renders it; an unstructured one as it was
    written, unfolded and decoded. The `headers` artifact holds the bytes either way, which
    is what makes it safe for the view to be a view.
    """
    raw = b.message(
        raw_headers=(
            b'From: "Alice  Example"   <alice@example.net>\r\n'
            b"Return-Path: <bounce@example.net>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Subject: spaced   out,\r\n\tand folded\r\n"
            b"X-Note: spaced   out,\r\n\tand folded"
        ),
        body=b"body",
    )
    body = dissect(client, raw)
    headers = body["messages"][0]["headers"]
    # Structured: parsed and rendered, so the quotes and the run of spaces are gone.
    assert headers["from"] == ["Alice  Example <alice@example.net>"]
    assert headers["return-path"] == ["bounce@example.net"]  # an address header here (F6)
    assert headers["content-type"] == ['text/plain; charset="utf-8"']
    # Unstructured: only the line break goes.
    assert headers["subject"] == ["spaced   out,\tand folded"]
    assert headers["x-note"] == ["spaced   out,\tand folded"]

    artifact = next(a for a in body["artifacts"] if a["kind"] == "headers")
    fetched = client.get(f"/v1/artifact/{body['dissect_id']}/{artifact['artifact_id']}")
    assert fetched.content == raw[: raw.index(b"\r\n\r\n")]


def test_the_registry_maps_what_the_pins_say(client: TestClient) -> None:
    """Which headers are structured is the interpreter's map, so it is pinned (F18)."""
    pins.check_registry_map()


def test_the_specification_names_the_structured_headers() -> None:
    """Case 69: SPEC §7 lists them by name, and the list is the one the service uses."""
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("**The structured headers are**")
    paragraph = text[start : text.index("\n\n", start)]
    named = set(re.findall(r"`([a-z-]+)`", paragraph))
    assert named == pins.STRUCTURED_HEADERS
