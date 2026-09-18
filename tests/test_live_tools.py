"""The optional tools against REAL containers, not fakes.

Never part of the default suite and never run in CI: it needs two images and a network. It
exists because the fakes prove our side of the contract and nothing about theirs — the shape
of a Tika call and a Gotenberg call is taken on trust everywhere else, and trust is what F15
found to be misplaced about the hardening flags we recommend.

    docker run -d --name md-tika -p 127.0.0.1:9998:9998 apache/tika:3.2.3.0
    docker run -d --name md-shot -p 127.0.0.1:3000:3000 gotenberg/gotenberg:8.37.0 \\
        gotenberg --chromium-disable-javascript=true --chromium-allow-list='^file:///.*'
    MAIL_DISSECT_LIVE_TOOLS=1 uv run pytest tests/test_live_tools.py -v -m live
"""

from __future__ import annotations

import os

import builders as b
import pytest
from conftest import FakeClock, dissect
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.settings import Settings

TIKA_URL = os.environ.get("MAIL_DISSECT_TIKA_URL", "http://127.0.0.1:9998/tika")
SHOT_URL = os.environ.get(
    "MAIL_DISSECT_SHOT_URL", "http://127.0.0.1:3000/forms/chromium/screenshot/html"
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("MAIL_DISSECT_LIVE_TOOLS") != "1",
        reason="needs real Tika and renderer containers; set MAIL_DISSECT_LIVE_TOOLS=1",
    ),
]

DOCUMENT_TEXT = "Contact fraud@evil.example about invoice 7"


@pytest.fixture
def live_client(settings: Settings, clock: FakeClock) -> TestClient:
    configured = Settings(
        **{**settings.model_dump(), "tika_url": TIKA_URL, "screenshot_url": SHOT_URL},
        _env_file=None,
    )
    return TestClient(create_app(configured, clock=clock))


def test_real_tika_extracts_the_text_we_then_scan(live_client: TestClient) -> None:
    """Test 52, against the image `compose.yml` pins."""
    raw = b.multipart(
        "mixed",
        b.part("text/plain", b"see the attachment"),
        b.part(
            "application/pdf",
            b.minimal_pdf(DOCUMENT_TEXT),
            encoding="base64",
            filename="invoice.pdf",
        ),
        headers={"From": "billing@example.net"},
    )
    with live_client as client:
        body = dissect(client, raw)
        assert body["tools"]["tika"] == "ok"

        attachment = body["messages"][0]["attachments"][0]
        assert attachment["text_artifact_id"], "the extracted text became an artifact"
        fetched = client.get(
            f"/v1/artifact/{body['dissect_id']}/{attachment['text_artifact_id']}"
        )
        assert DOCUMENT_TEXT in fetched.text

    # The candidates in the document join the one canonical list, with their own source.
    candidate = next(
        o for o in body["messages"][0]["observables"] if o["value"] == "fraud@evil.example"
    )
    assert candidate["sources"][0]["kind"] == "attachment"


def test_real_renderer_returns_an_image(live_client: TestClient) -> None:
    """Test 53, against the image `compose.yml` pins — and the flags it recommends."""
    raw = b.multipart(
        "mixed",
        b.part("text/html", b"<h1>Rendered</h1><p>by the real thing</p>"),
        headers={"From": "sender@example.net"},
    )
    with live_client as client:
        body = dissect(client, raw)
        assert body["tools"]["renderer"] == "ok", (
            "a renderer configured with --chromium-deny-list=.* answers 403 to every render, "
            "including the page it was asked to render (F15)"
        )
        shot = next(a for a in body["artifacts"] if a["kind"] == "screenshot")
        image = client.get(f"/v1/artifact/{body['dissect_id']}/{shot['artifact_id']}")

    assert image.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert shot["mime"] == "image/png"
    assert shot["size"] > 1000


def test_an_embedded_image_reaches_the_renderer(live_client: TestClient) -> None:
    """SPEC §14.2: `cid:` parts travel as assets, and the real renderer accepts them."""
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000000100000001080600000"
        "01f15c4890000000a49444154789c6360000002000100ffff03000006"
        "000557bfabd40000000049454e44ae426082"
    )
    raw = b.multipart(
        "related",
        b.part("text/html", b'<p>logo: <img src="cid:logo001"></p>'),
        b.part("image/png", png, content_id="<logo001>", disposition="inline", filename="l.png"),
    )
    with live_client as client:
        body = dissect(client, raw)
    assert body["tools"]["renderer"] == "ok"
    assert [a for a in body["artifacts"] if a["kind"] == "screenshot"]
