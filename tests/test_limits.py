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

    assert at_limit["flags"] == []
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
