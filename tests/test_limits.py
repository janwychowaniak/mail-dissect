"""Limits on what one message can make the scan do: SPEC §15.

Each limit is tested as a pair: at the limit the material is read, one past it the limit
applies. The case at the limit is the control for the case past it, since the two differ by
one character.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import builders as b
import httpx
import pytest
from conftest import FakeClock, dissect
from fastapi.testclient import TestClient

from mail_dissect import observables
from mail_dissect.app import create_app
from mail_dissect.headers import STRUCTURED_HEADER_LIMIT, UNSTRUCTURED_HEADER_LIMIT
from mail_dissect.observables import MAX_RUN_LENGTH
from mail_dissect.settings import Settings

PREFIX = "http://run.example.net/"


def _run(length: int) -> str:
    """One run of non-white-space characters, `length` long, that is itself a URL."""
    return PREFIX + "x" * (length - len(PREFIX))


def _text(run: str) -> str:
    return f"lead.example.net {run} tail.example.net"


def _in_header(text: str) -> bytes:
    return b.message({"Subject": "s", "X-Run": text}, body=b"body")


def _in_body_text(text: str) -> bytes:
    return b.message({"Subject": "s"}, body=text.encode())


def _in_html(text: str) -> bytes:
    return b.message({"Subject": "s", "Content-Type": "text/html"}, body=f"<p>{text}</p>".encode())


def _in_document(_text: str) -> bytes:
    return b.multipart(
        "mixed",
        b.part("text/plain", b"see the document"),
        b.part("application/pdf", b"%PDF-1.4", encoding="base64", filename="d.pdf"),
        headers={"Subject": "s"},
    )


UNITS: dict[str, Callable[[str], bytes]] = {
    "header": _in_header,
    "body text": _in_body_text,
    "html text": _in_html,
    "document text": _in_document,
}


def _dissect(settings: Settings, clock: FakeClock, unit: str, text: str) -> dict:
    """The message for `unit`; for a document, the text extractor answers with `text`."""

    def tika(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=text)

    configured = settings
    if unit == "document text":
        configured = settings.model_copy(update={"tika_url": "http://tika.invalid/tika"})
    app = create_app(configured, transport=httpx.MockTransport(tika), clock=clock)
    with TestClient(app) as client:
        return dissect(client, UNITS[unit](text))


def _values(body: dict) -> list[str]:
    return [item["value"] for item in body["messages"][0]["observables"]]


@pytest.mark.parametrize("unit", list(UNITS))
def test_a_run_at_the_limit_is_read_and_one_past_it_is_skipped(
    unit: str, settings: Settings, clock: FakeClock
) -> None:
    """`[D29]`: a run of `MAX_RUN_LENGTH` characters is read; one character more, and the
    whole run is skipped, in every unit the grammar reads.

    Skipped means nothing from it: not the URL, and not the host a cut URL would still give.
    The words either side are read in both cases, because skipping is exact for the rest of
    the text. The flag is deterministic here, unlike `truncated` from a time overrun.
    """
    at_limit = _dissect(settings, clock, unit, _text(_run(MAX_RUN_LENGTH)))
    past_it = _dissect(settings, clock, unit, _text(_run(MAX_RUN_LENGTH + 1)))

    # A header that long is past its own limit `[D33]`, which also says `truncated`; it is
    # still scanned as written, so the run limit applies to it as to the others.
    assert at_limit["flags"] == (["truncated"] if unit == "header" else [])
    assert _run(MAX_RUN_LENGTH) in _values(at_limit)
    assert "run.example.net" in _values(at_limit)
    assert "truncated" in past_it["flags"]
    assert not [value for value in _values(past_it) if "run.example.net" in value]
    for body in (at_limit, past_it):
        assert {"lead.example.net", "tail.example.net"} <= set(_values(body))


def test_white_space_of_any_kind_ends_a_run(settings: Settings, clock: FakeClock) -> None:
    """A run ends at any character the grammar's `\\s` matches, here U+00A0.

    `MAX_RUN_LENGTH + 1` characters with one no-break space among them are two runs, each
    under the limit, and both are read.
    """
    first = "http://one.example.net/" + "x" * 1000
    second = "http://two.example.net/"
    second += "x" * (MAX_RUN_LENGTH + 1 - len(first) - 1 - len(second))
    text = f"{first}\u00a0{second}"
    assert len(text) == MAX_RUN_LENGTH + 1

    body = _dissect(settings, clock, "body text", text)

    assert body["flags"] == []
    assert {first, second} <= set(_values(body))


def test_finding_long_runs_costs_less_than_reading_them(
    settings: Settings, clock: FakeClock
) -> None:
    """`[D13]`: a limit must be cheaper than what it protects against.

    A search for long runs that may start inside a run counts to the end of the run again from
    every position in it, as long as enough text follows in what it searches. The scan's
    chunks end at the first white space after `_CHUNK` characters, so a run close to the limit
    usually ends its chunk and leaves nothing to count into; the shape here is one where it
    does not. A run just short of the chunk size, then a run past the limit, so the chunk
    holds both: such a search takes about eight seconds for each pair, and one anchored at
    the start of a run takes milliseconds. Two runs at the limit, one after the other, were
    tried first and were fast either way, because each ended its own chunk.
    """
    pair = "x" * (observables._CHUNK - 600) + " " + "y" * (MAX_RUN_LENGTH + 1) + " "
    text = pair * 2
    assert len(list(observables._chunks(text))) == 3

    started = time.perf_counter()
    body = _dissect(settings, clock, "body text", text)
    elapsed = time.perf_counter() - started

    assert body["flags"] == ["truncated"]
    assert elapsed < 5.0, f"took {elapsed:.1f}s for two runs past the limit"


# -- header limits `[D33]` and part parameters `[D34]` -----------------------------------------


def _filled(head: str, tail: str, length: int) -> str:
    """`head`, parameters that mean nothing, then `tail`: a header value exactly `length` long."""
    filler = ""
    index = 0
    while len(head) + len(filler) + len(tail) < length:
        filler += f"; x{index}=y"
        index += 1
    value = head + filler + tail
    excess = len(value) - length
    if excess:
        # Shorten the last parameter's value, which stays a parameter.
        value = head + filler[:-excess] + tail
    assert len(value) == length
    return value


def _plain(settings: Settings, clock: FakeClock, raw: bytes) -> dict:
    with TestClient(create_app(settings, clock=clock)) as client:
        return dissect(client, raw)


def _address_list(length: int) -> str:
    """An address list exactly `length` long, its first display name an encoded-word."""
    value = "=?utf-8?q?Caf=C3=A9?= <first@example.net>"
    index = 0
    while len(value) < length - 40:
        value += f", a{index}@example.net"
        index += 1
    value += ", last@example.org"
    pad = length - len(value)
    return value[: -len("last@example.org")] + "l" * pad + "last@example.org"


def test_a_structured_header_at_its_limit_is_read_and_one_past_it_is_kept_as_written(
    settings: Settings, clock: FakeClock
) -> None:
    """`[D33]`: an address header is structured, and read up to 8,192 characters.

    At the limit the list is decomposed and the display name decoded. One character more and
    the value is kept as written, and `addresses{}` has one entry with nulls; the header is
    still scanned, so its addresses are still candidates.
    """
    at, past = (_address_list(STRUCTURED_HEADER_LIMIT + n) for n in (0, 1))
    assert (len(at), len(past)) == (STRUCTURED_HEADER_LIMIT, STRUCTURED_HEADER_LIMIT + 1)
    read = _plain(settings, clock, b.message({"To": at}, body=b"x"))["messages"][0]
    kept_body = _plain(settings, clock, b.message({"To": past}, body=b"x"))
    kept = kept_body["messages"][0]

    assert read["headers"]["to"][0].startswith("Café <first@example.net>")
    assert len(read["addresses"]["to"]) > 300
    assert read["addresses"]["to"][0]["domain"] == "example.net"
    assert "truncated" in kept_body["flags"]
    assert kept["headers"]["to"] == [past]
    assert kept["addresses"]["to"] == [
        {"display_name": None, "address": None, "local_part": None, "domain": None}
    ]
    assert "first@example.net" in [o["value"] for o in kept["observables"]]


def test_an_unstructured_header_at_its_limit_is_decoded_and_one_past_it_is_kept_as_written(
    settings: Settings, clock: FakeClock
) -> None:
    """`[D33]`: `Subject` and every name the registry does not know are read up to 65,536."""
    word = "=?utf-8?q?caf=C3=A9?="
    for name in ("Subject", "X-Note"):
        at, past = (
            word + " " + "x " * ((UNSTRUCTURED_HEADER_LIMIT + n - len(word) - 1) // 2)
            for n in (0, 2)
        )
        at, past = at[:UNSTRUCTURED_HEADER_LIMIT], past[: UNSTRUCTURED_HEADER_LIMIT + 1]
        read = _plain(settings, clock, b.message({name: at}, body=b"x"))
        kept = _plain(settings, clock, b.message({name: past}, body=b"x"))
        key = name.lower()
        assert read["messages"][0]["headers"][key][0].startswith("café x"), name
        assert "truncated" not in read["flags"], name
        assert kept["messages"][0]["headers"][key] == [past], name
        assert "truncated" in kept["flags"], name


def test_the_class_of_a_header_is_the_registry_s(settings: Settings, clock: FakeClock) -> None:
    """The same 8,193 characters are past the limit of a structured header and within that of
    an unstructured one. `In-Reply-To` is structured on 3.13 (`tests/pins.py`)."""
    value = "=?utf-8?q?caf=C3=A9?= " + "<a@example.net> " * 600
    value = value[: STRUCTURED_HEADER_LIMIT + 1]
    body = _plain(settings, clock, b.message({"In-Reply-To": value, "X-Note": value}, body=b"x"))
    headers = body["messages"][0]["headers"]
    assert headers["in-reply-to"] == [value]
    assert headers["x-note"][0].startswith("café")


def test_headers_past_the_deadline_are_kept_as_written(
    settings: Settings, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`[D10]`: the deadline is asked between headers. The clock passes it once the first
    header has been read; the rest are kept as written, in the shape of a header past its
    limit, so none is lost. The control is the same message with the clock standing still."""
    from mail_dissect import headers

    read = headers._read
    advance = {"seconds": 0.0}

    def read_then_advance(name: str, value: str) -> tuple[str, bool]:
        result = read(name, value)
        clock.advance(advance["seconds"])
        return result

    monkeypatch.setattr(headers, "_read", read_then_advance)
    raw = b.message(
        [
            ("Subject", "=?utf-8?q?caf=C3=A9?="),
            ("X-Note", "=?utf-8?q?th=C3=A9?="),
            ("To", "=?utf-8?q?Caf=C3=A9?= <a@example.net>"),
        ],
        body=b"x",
    )
    still = _plain(settings, clock, raw)
    advance["seconds"] = settings.dissect_timeout_seconds + 1
    late = _plain(settings, clock, raw)

    assert still["messages"][0]["headers"]["x-note"] == ["thé"]
    assert still["messages"][0]["addresses"]["to"][0]["domain"] == "example.net"
    late_message = late["messages"][0]
    assert late_message["headers"]["subject"] == ["café"]
    assert late_message["headers"]["x-note"] == ["=?utf-8?q?th=C3=A9?="]
    assert late_message["headers"]["to"] == ["=?utf-8?q?Caf=C3=A9?= <a@example.net>"]
    assert late_message["addresses"]["to"][0]["domain"] is None
    assert "truncated" in late["flags"]


def _part_of(body: dict, index: int) -> dict:
    return body["messages"][0]["mime_parts"][index]


def test_a_charset_past_the_limit_is_not_read(settings: Settings, clock: FakeClock) -> None:
    """`[D34]`: at the limit the declared charset is read; one character more, and the text is
    read as undeclared, with no `encoding_fallback`: no declaration was read and not taken."""
    for n, text, charset in ((0, "ą", "iso-8859-2"), (1, "±", None)):
        value = _filled("text/plain", "; charset=iso-8859-2", STRUCTURED_HEADER_LIMIT + n)
        raw = b.message({"Content-Type": value}, body=b"\xb1")
        body = _plain(settings, clock, raw)
        assert body["messages"][0]["body"]["text"].strip() == text, n
        assert _part_of(body, 0)["charset_declared"] == charset, n
        assert "encoding_fallback" not in body["flags"], n
        assert ("truncated" in body["flags"]) is bool(n), n


def test_a_name_past_the_limit_is_not_read_and_not_looked_for_elsewhere(
    settings: Settings, clock: FakeClock
) -> None:
    """`[D34]`: the name in `Content-Disposition` is not read, and neither is `name` in
    `Content-Type` in its place, since `filename` may well have been written in the first."""
    for n, expected in ((0, "a.pdf"), (1, None)):
        disposition = _filled("attachment", '; filename="a.pdf"', STRUCTURED_HEADER_LIMIT + n)
        raw = b.multipart(
            "mixed",
            b.part("text/plain", b"see the file"),
            b.part(
                "application/octet-stream",
                b"data",
                extra={"Content-Disposition": disposition},
            ).replace(
                b"Content-Type: application/octet-stream",
                b'Content-Type: application/octet-stream; name="b.txt"',
            ),
        )
        body = _plain(settings, clock, raw)
        attachment = body["messages"][0]["attachments"][0]
        assert attachment["filename"] == expected, n
        assert attachment["disposition"] == "attachment", n
        # A part's header is no header of the message, so this `truncated` can come only from
        # the parameters left unread; in the two tests around this one the long header is
        # also the message's, and past its own limit.
        assert ("truncated" in body["flags"]) is bool(n), n


def test_a_boundary_past_the_limit_leaves_the_multipart_a_leaf(
    settings: Settings, clock: FakeClock
) -> None:
    """`[D34]`: with its boundary unread, a multipart does not segment, and is a leaf by the
    rule of §6.1: one part, listed as an attachment. The parser's report of a multipart with
    no boundary describes our limit, so it gives `truncated`, not `malformed_mime`."""
    for n in (0, 1):
        value = _filled("multipart/mixed", '; boundary="BB"', STRUCTURED_HEADER_LIMIT + n)
        raw = b.multipart("mixed", b.part("text/plain", b"one"), b.part("text/plain", b"two"))
        raw = raw.replace(
            b'Content-Type: multipart/mixed; boundary="BB"', f"Content-Type: {value}".encode()
        )
        body = _plain(settings, clock, raw)
        message = body["messages"][0]
        if n == 0:
            assert len(message["mime_parts"]) == 3 and body["flags"] == []
        else:
            assert [part["content_type"] for part in message["mime_parts"]] == ["multipart/mixed"]
            assert [a["part_index"] for a in message["attachments"]] == [0]
            assert body["flags"] == ["truncated"]


def test_every_parameter_reader_asks_the_bounded_method() -> None:
    """The bound sits in one private method of `email.message.Message`; this interpreter must
    still send `get_param`, `get_boundary` and `get_filename` through it (`tests/pins.py`)."""
    import pins

    pins.check_parameter_funnel()
