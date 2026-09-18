"""The optional tools: SPEC §14.

Acceptance cases 13, 52, 53, 54, 58, 59, 62.
"""

from __future__ import annotations

from collections.abc import Callable

import builders as b
import httpx
import pytest
from conftest import FakeClock, dissect
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.settings import Settings

TIKA_URL = "http://tika.invalid/tika"
SHOT_URL = "http://renderer.invalid/forms/chromium/screenshot/html"
PNG = b"\x89PNG\r\n\x1a\n" + b"fake image bytes"
PDF = b"%PDF-1.4 a document with text in it"


def _with_tools(
    settings: Settings,
    clock: FakeClock,
    handler: Callable[[httpx.Request], httpx.Response],
    **overrides: object,
) -> TestClient:
    configured = Settings(
        **{
            **settings.model_dump(),
            "tika_url": TIKA_URL,
            "screenshot_url": SHOT_URL,
            **overrides,
        },
        _env_file=None,
    )
    app = create_app(configured, transport=httpx.MockTransport(handler), clock=clock)
    return TestClient(app)


def _document_message() -> bytes:
    return b.multipart(
        "mixed",
        b.part("text/plain", b"see the attachment"),
        b.part("application/pdf", PDF, encoding="base64", filename="faktura.pdf"),
        headers={"From": "sender@example.net", "Subject": "invoice"},
    )


def _html_message() -> bytes:
    return b.multipart(
        "mixed",
        b.part("text/html", b"<p>Rendered content</p>"),
        headers={"From": "sender@example.net", "Subject": "html"},
    )


DOCUMENT_TEXT = "Contact fraud@evil.example or visit hxxp://bad[.]host now."


def _tools_up(
    tika_text: str = DOCUMENT_TEXT,
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(200, text=tika_text)
        return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})

    return handler


def test_tools_disabled_make_no_calls(client: TestClient) -> None:
    """Test 13: no address means the tool does not exist for this deployment `[D1]`.

    The autouse socket guard is half the assertion: `disabled` must cost no traffic at all.
    """
    body = dissect(client, _document_message())
    assert body["tools"] == {"tika": "disabled", "renderer": "disabled"}
    assert body["messages"][0]["attachments"][0]["text_artifact_id"] is None
    assert not [a for a in body["artifacts"] if a["kind"] in ("attachment_text", "screenshot")]
    # The rest of the dissection is unchanged.
    assert body["messages"][0]["attachments"][0]["sha256"]
    assert body["flags"] == []


def test_working_text_extractor(settings: Settings, clock: FakeClock) -> None:
    """Test 52: the text becomes an artifact, and its candidates join the ONE list."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="Contact fraud@evil.example about invoice 7.")

    with _with_tools(settings, clock, handler, screenshot_url="") as client:
        body = dissect(client, _document_message())

    assert body["tools"]["tika"] == "ok"
    assert calls[0].method == "PUT"
    assert calls[0].headers["accept"] == "text/plain"
    assert calls[0].headers["content-type"] == "application/pdf"
    assert calls[0].content == PDF, "the tool gets the decoded bytes, not the encoded ones"

    attachment = body["messages"][0]["attachments"][0]
    artifact = next(a for a in body["artifacts"] if a["kind"] == "attachment_text")
    assert attachment["text_artifact_id"] == artifact["artifact_id"]
    assert artifact["part_index"] == attachment["part_index"]

    candidate = next(
        o for o in body["messages"][0]["observables"] if o["value"] == "fraud@evil.example"
    )
    assert candidate["sources"] == [
        {
            "kind": "attachment",
            "header_name": None,
            "header_index": None,
            "part_index": attachment["part_index"],
        }
    ]


def test_only_documents_are_sent(settings: Settings, clock: FakeClock) -> None:
    """SPEC §14.1: never images, archives or executables."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="text")

    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body"),
        b.part("image/png", PNG, encoding="base64", filename="logo.png"),
        b.part("application/zip", b"PK\x03\x04zip", encoding="base64", filename="archive.zip"),
    )
    with _with_tools(settings, clock, handler, screenshot_url="") as client:
        body = dissect(client, raw)
    assert calls == []
    # An address with nothing to ask about is `skipped`, not `ok` and not `down` [D1].
    assert body["tools"]["tika"] == "skipped"


def test_working_renderer(settings: Settings, clock: FakeClock) -> None:
    """Test 53: a screenshot artifact, attributable to its message."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})

    with _with_tools(settings, clock, handler, tika_url="") as client:
        body = dissect(client, _html_message())

    assert body["tools"]["renderer"] == "ok"
    assert captured[0].method == "POST"
    assert b"index.html" in captured[0].content
    artifact = next(a for a in body["artifacts"] if a["kind"] == "screenshot")
    assert artifact["message_index"] == 0
    assert artifact["mime"] == "image/png"
    assert artifact["size"] == len(PNG)


def test_embedded_resources_are_sent_as_assets(settings: Settings, clock: FakeClock) -> None:
    """SPEC §14.2: `cid:` references point at parts sent beside the HTML, named by index."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})

    raw = b.multipart(
        "related",
        b.part("text/html", b'<p>See <img src="cid:logo001"></p>'),
        b.part("image/png", PNG, content_id="<logo001>", disposition="inline", filename="l.png"),
    )
    with _with_tools(settings, clock, handler, tika_url="") as client:
        dissect(client, raw)

    sent = captured[0].content
    assert b"cid-2.png" in sent, "the asset is named from the part index, not the filename"
    assert b'src="cid-2.png"' in sent, "the reference was rewritten to point at the asset"
    assert b"cid:logo001" not in sent


def test_nested_message_gets_its_own_screenshot(settings: Settings, clock: FakeClock) -> None:
    """Test 59 `[D3]`: the nested message is often the one that matters."""
    inner = b.multipart("alternative", b.part("text/html", b"<p>inner</p>"), boundary="IN")
    raw = b.multipart("mixed", b.part("text/html", b"<p>outer</p>"), b.nested(inner), boundary="BB")
    with _with_tools(settings, clock, _tools_up(), tika_url="") as client:
        body = dissect(client, raw)

    shots = [a for a in body["artifacts"] if a["kind"] == "screenshot"]
    assert sorted(a["message_index"] for a in shots) == [0, 1]


def test_the_worst_outcome_wins(settings: Settings, clock: FakeClock) -> None:
    """Test 58 `[D5]`: a partial success reported as a full one would be a silent failure."""

    def handler(request: httpx.Request) -> httpx.Response:
        # The second document times out; the first is fine.
        if b"second" in request.content:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, text="extracted text")

    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"two documents"),
        b.part("application/pdf", b"%PDF-1.4 first", encoding="base64", filename="a.pdf"),
        b.part("application/pdf", b"%PDF-1.4 second", encoding="base64", filename="b.pdf"),
    )
    with _with_tools(settings, clock, handler, screenshot_url="") as client:
        body = dissect(client, raw)

    assert body["tools"]["tika"] == "timeout", "two successes and one timeout is not `ok`"
    first, second = body["messages"][0]["attachments"]
    assert first["text_artifact_id"] is not None
    assert second["text_artifact_id"] is None, "what succeeded is read from the entries"
    assert body["ok"] is True  # a tool problem is not an error (SPEC §16)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (httpx.ConnectError, "down"),
        (httpx.ReadTimeout, "timeout"),
    ],
)
def test_a_tool_that_fails_does_not_fail_the_dissection(
    settings: Settings, clock: FakeClock, failure: type[httpx.HTTPError], expected: str
) -> None:
    """Test 13, second half: without them the answer is poorer, never wrong."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise failure("boom", request=request)

    with _with_tools(settings, clock, handler) as client:
        body = dissect(client, _document_message())

    assert body["ok"] is True
    assert body["tools"]["tika"] == expected
    assert body["messages"][0]["attachments"][0]["sha256"]
    assert body["flags"] == []  # a tool problem is not a flag either


def test_a_renderer_that_answers_with_something_else_is_down(
    settings: Settings, clock: FakeClock
) -> None:
    """A renderer returning JSON is not working, whatever status code it chose."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"error": "nope"})

    with _with_tools(settings, clock, handler, tika_url="") as client:
        body = dissect(client, _html_message())
    assert body["tools"]["renderer"] == "down"
    assert not [a for a in body["artifacts"] if a["kind"] == "screenshot"]


def test_the_deterministic_core_does_not_move(settings: Settings, clock: FakeClock) -> None:
    """Test 62 `[D9]`: the same message, with and without the text extractor.

    Entries from headers and content keep their positions; what the document adds is
    appended. A consumer comparing two dissections must not see the list reshuffle.
    """
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body mentions body.example and 10.0.0.1"),
        b.part("application/pdf", PDF, encoding="base64", filename="doc.pdf"),
        headers={"From": "sender@example.net", "X-Origin": "https://header.example/x"},
    )
    with TestClient(create_app(settings, clock=clock)) as client:
        without = dissect(client, raw)["messages"][0]["observables"]
    with _with_tools(settings, clock, _tools_up(), screenshot_url="") as client:
        with_tika = dissect(client, raw)["messages"][0]["observables"]

    core = with_tika[: len(without)]
    assert [o["value"] for o in core] == [o["value"] for o in without]
    assert [o["type"] for o in core] == [o["type"] for o in without]
    tail = with_tika[len(without) :]
    assert tail, "the document contributed nothing, so the test proves nothing"
    assert all(source["kind"] == "attachment" for o in tail for source in o["sources"])


def test_the_whole_budget_is_enforced_between_units(settings: Settings, clock: FakeClock) -> None:
    """Test 54: a partial result with `truncated`, at HTTP 200 and `ok: true`.

    The clock is injected and advances on every reading, so the budget runs out at a known
    boundary instead of whenever the machine happens to be slow.
    """

    class TickingClock(FakeClock):
        def __call__(self) -> float:
            self.now += 40.0
            return self.now

    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"body"),
        *[b.nested(b.message({"From": f"n{i}@example.net"}, body=b"x")) for i in range(4)],
    )
    with TestClient(create_app(settings, clock=TickingClock())) as client:
        body = dissect(client, raw)
    with TestClient(create_app(settings, clock=clock)) as client:
        whole = dissect(client, raw)

    assert body["ok"] is True
    assert "truncated" in body["flags"]
    assert body["messages"], "what was dissected before the cut is still returned"
    assert body["artifacts"], "artifacts written before the cut stay available"
    # The flag alone proves nothing: it is also set at the end of a dissection that ran to
    # completion past its budget. The result has to be genuinely SHORTER than the material,
    # which is what a deadline checked BETWEEN units of work buys [D10].
    assert len(whole["messages"]) == 5 and whole["flags"] == []
    assert len(body["messages"]) < len(whole["messages"])
