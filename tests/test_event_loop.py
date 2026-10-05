"""The event loop only awaits: SPEC §14.3, acceptance case 74, and the deadline `[D10]`.

`/v1/health` is answered on the same event loop as `POST /v1/dissect`. Any work a dissection
does on that loop is work during which health cannot answer. Before 0.7.0 that was everything
after parsing: building the messages, scanning them, scanning a document's text, the
`source` hashes and the serialisation. A large message stalled health for as long as all of
that took.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

import builders as b
import httpx
import pytest
from conftest import FakeClock, dissect
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from mail_dissect import app as app_module
from mail_dissect import dissect as dissect_module
from mail_dissect import routes
from mail_dissect.app import create_app
from mail_dissect.artifacts import ArtifactStore
from mail_dissect.models import DissectResponse
from mail_dissect.observables import Collector
from mail_dissect.settings import Settings

# How long a stage waits for health to answer. On the loop, health cannot answer at all and
# the wait runs out; off it, health answers in milliseconds. The two are far apart.
WAIT_SECONDS = 2.0

PNG = b"\x89PNG\r\n\x1a\n" + b"fake image bytes"


def _tools(request: httpx.Request) -> httpx.Response:
    if request.method == "PUT":
        return httpx.Response(200, text="the document mentions document.example.net")
    return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})


def _message() -> bytes:
    """Every stage has material: headers, text, HTML with a link, a document, a render."""
    return b.multipart(
        "mixed",
        b.multipart(
            "alternative",
            b.part("text/plain", b"text mentions text.example.net"),
            b.part("text/html", b'<p>html <a href="http://link.example.net/">here</a></p>'),
            boundary="AA",
        ),
        b.part("application/pdf", b"%PDF-1.4 text", encoding="base64", filename="doc.pdf"),
        headers={"From": "sender@example.net", "Subject": "stages"},
    )


class _Stage:
    """Holds the first matching call of one function until health has answered, or not."""

    def __init__(self, when: Callable[..., bool]) -> None:
        self._when = when
        self._claimed = threading.Lock()
        self.entered = threading.Event()
        self.health_done = threading.Event()
        self.answered: bool | None = None

    def wrap(self, original: Callable[..., Any]) -> Callable[..., Any]:
        def held(*args: Any, **kwargs: Any) -> Any:
            if self._when(*args, **kwargs) and self._claimed.acquire(blocking=False):
                self.entered.set()
                self.answered = self.health_done.wait(WAIT_SECONDS)
            return original(*args, **kwargs)

        return held


def _source_kind(kind: str) -> Callable[..., bool]:
    return lambda _self, _text, source: source.kind == kind


def _artifact_kind(kind: str) -> Callable[..., bool]:
    return lambda _self, _dissect_id, artifact_kind, *_args, **_kwargs: artifact_kind == kind


def _always(*_args: Any, **_kwargs: Any) -> bool:
    return True


def _the_dissection(_self: object, content: object) -> bool:
    # Health is rendered by the same class; only the dissection's answer is held.
    return isinstance(content, dict) and "messages" in content


# (target, attribute, which call, answered while it runs)
STAGES: dict[str, tuple[object, str, Callable[..., bool], bool]] = {
    "header scan": (Collector, "feed_text", _source_kind("header"), True),
    "text scan": (Collector, "feed_text", _source_kind("body_text"), True),
    "html text scan": (Collector, "feed_text", _source_kind("body_html"), True),
    "html parse": (dissect_module, "scan_html", _always, True),
    "artifact write": (ArtifactStore, "put", _artifact_kind("eml"), True),
    "document text scan": (Collector, "feed_text", _source_kind("attachment"), True),
    "document text write": (ArtifactStore, "put", _artifact_kind("attachment_text"), True),
    "render payload": (dissect_module, "_render_payload", _always, True),
    "screenshot write": (ArtifactStore, "put", _artifact_kind("screenshot"), True),
    "observables": (Collector, "finish", _always, True),
    "source hashes": (dissect_module, "hash_bytes", _always, True),
    "model dump": (DissectResponse, "model_dump", _always, True),
    "json render": (JSONResponse, "render", _the_dissection, True),
    # The positive control: reading the request is the loop's own work, so health cannot
    # answer while it runs. Without this case a harness that never blocked anything would
    # pass every row above.
    "control: request body": (routes, "_message_bytes", _always, False),
}


@pytest.mark.parametrize("name", list(STAGES))
def test_health_answers_while_a_dissection_runs(
    name: str, settings: Settings, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 74: health answers while each stage after the request is read is in progress.

    The stage is held in the middle of its work until health has answered. If the stage runs
    on the event loop, health cannot answer while it is held, the wait runs out, and the
    stage records that it was not answered.

    Health is asked only after the stage has been entered. Asked earlier, it would answer
    while the dissection was still parsing in its worker thread, and every row would pass
    whatever the stage did.
    """
    target, attribute, when, expected = STAGES[name]
    stage = _Stage(when)
    monkeypatch.setattr(target, attribute, stage.wrap(getattr(target, attribute)))
    configured = settings.model_copy(
        update={"tika_url": "http://tika.invalid/tika", "screenshot_url": "http://shot.invalid"}
    )
    app = create_app(configured, transport=httpx.MockTransport(_tools), clock=clock)

    outcome: dict[str, dict[str, Any]] = {}
    with TestClient(app) as client:
        worker = threading.Thread(target=lambda: outcome.update(body=dissect(client, _message())))
        worker.start()
        assert stage.entered.wait(30), "the dissection never reached the stage"
        health = client.get("/v1/health")
        stage.health_done.set()
        worker.join(30)

    assert health.status_code == 200
    # The held dissection still finishes, with every tool answering, so the stage was the
    # one this row describes and nothing failed around it.
    assert outcome["body"]["tools"] == {"tika": "ok", "renderer": "ok"}
    assert outcome["body"]["flags"] == []
    assert stage.answered is expected


def test_health_answers_while_the_store_is_swept(
    settings: Settings, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep waits for the store's lock, which a write of a large artifact holds.

    On the loop, that wait would be the loop's wait. The sweep is held the same way as the
    stages above, with the interval shortened so that it runs within the test.
    """
    stage = _Stage(_always)
    monkeypatch.setattr(ArtifactStore, "sweep", stage.wrap(ArtifactStore.sweep))
    monkeypatch.setattr(app_module, "SWEEP_INTERVAL_SECONDS", 0.01)

    with TestClient(create_app(settings, clock=clock)) as client:
        assert stage.entered.wait(30), "the sweep never ran"
        health = client.get("/v1/health")
        stage.health_done.set()

    assert health.status_code == 200
    assert stage.answered is True


def test_a_message_scanned_after_the_deadline_gives_no_candidates(
    settings: Settings, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`[D10]`: the deadline is checked between messages, before each message's scan.

    The clock passes the deadline as soon as the outer message has been scanned. The nested
    message is still returned whole, since it was parsed in time, but its scan does not
    start. `truncated` alone would prove nothing here: it is also set at the end of a
    dissection that ran to completion past its budget. What shows the check is a message
    whose material has a candidate and whose list is empty, next to the same message read
    with the clock standing still.
    """
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"outer mentions outer.example.net"),
        b.nested(b.message({"From": "n@example.org"}, body=b"inner mentions inner.example.net")),
    )
    scan = dissect_module._scan_observables
    advance = {"seconds": 0.0}

    def scan_then_advance(parsed: Any, *args: Any, **kwargs: Any) -> Any:
        collector = scan(parsed, *args, **kwargs)
        if parsed.index == 0:
            clock.advance(advance["seconds"])
        return collector

    monkeypatch.setattr(dissect_module, "_scan_observables", scan_then_advance)

    def values(message: dict[str, Any]) -> list[str]:
        return [item["value"] for item in message["observables"]]

    with TestClient(create_app(settings, clock=clock)) as client:
        still = dissect(client, raw)
        advance["seconds"] = settings.dissect_timeout_seconds + 1
        late = dissect(client, raw)

    assert still["flags"] == []
    assert "inner.example.net" in values(still["messages"][1])
    assert "truncated" in late["flags"]
    assert "outer.example.net" in values(late["messages"][0])
    assert late["messages"][1]["headers"]["from"] == ["n@example.org"]
    assert values(late["messages"][1]) == []
