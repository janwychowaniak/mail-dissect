"""The artifact store and its endpoint: SPEC §13. Cases 14, 18, 19, 31, 55, 57."""

from __future__ import annotations

from pathlib import Path

from conftest import SIMPLE, FakeClock, dissect
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.artifacts import content_disposition, sanitise_filename
from mail_dissect.settings import Settings


def _eml_id(body: dict) -> str:
    return next(a["artifact_id"] for a in body["artifacts"] if a["kind"] == "eml")


def test_eml_artifact_is_the_input_bytes(client: TestClient) -> None:
    """[D12]: original bytes, never a reconstruction — the ground for every hash."""
    body = dissect(client, SIMPLE)
    response = client.get(f"/v1/artifact/{body['dissect_id']}/{_eml_id(body)}")
    assert response.status_code == 200
    assert response.content == SIMPLE


def test_artifact_response_never_echoes_the_message(client: TestClient) -> None:
    """Test 57: the only place hostile material returns to a browser (SPEC §13.3)."""
    body = dissect(client, SIMPLE)
    response = client.get(f"/v1/artifact/{body['dissect_id']}/{_eml_id(body)}")
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"].startswith("attachment;")


def test_filename_sanitising_strips_paths_and_control_characters() -> None:
    """A CR or LF in a filename splits the response headers apart; a path escapes the store."""
    assert sanitise_filename("../../etc/passwd", "x.bin") == "passwd"
    assert sanitise_filename("in\r\nX-Injected: yes.pdf", "x.bin") == "inX-Injected: yes.pdf"
    assert sanitise_filename("C:\\windows\\system32\\evil.exe", "x.bin") == "evil.exe"
    assert sanitise_filename("", "x.bin") == "x.bin"
    assert sanitise_filename("..", "x.bin") == "x.bin"
    long_name = sanitise_filename("a" * 300 + ".pdf", "x.bin")
    assert len(long_name) == 100 and long_name.endswith(".pdf")
    header = content_disposition("faktura€.pdf")
    assert "filename*=UTF-8''faktura%E2%82%AC.pdf" in header
    assert 'filename="faktura_.pdf"' in header  # ASCII fallback, nothing raw


def test_no_listing_endpoint(client: TestClient) -> None:
    """Test 18: one identifier must not be enough to derive the rest (SPEC §4)."""
    body = dissect(client)
    response = client.get(f"/v1/artifact/{body['dissect_id']}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ARTIFACT_NOT_FOUND"
    assert "artifacts" not in response.text.lower().replace("artifacts are not listable", "")


def test_unknown_artifact_id_with_a_valid_dissect_id(client: TestClient) -> None:
    """Test 55."""
    body = dissect(client)
    response = client.get(f"/v1/artifact/{body['dissect_id']}/{'A' * 22}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ARTIFACT_NOT_FOUND"


def test_expired_artifact_is_410_without_a_restart(settings: Settings, clock: FakeClock) -> None:
    """Test 14: expiry is observable because the index keeps a tombstone (SPEC §13.4).

    The clock is injected, so the test states the passage of time instead of sleeping.
    """
    app = create_app(settings, clock=clock)
    with TestClient(app) as client:
        body = dissect(client)
        artifact_id = _eml_id(body)
        assert client.get(f"/v1/artifact/{body['dissect_id']}/{artifact_id}").status_code == 200

        clock.advance(settings.artifact_ttl_seconds + 1)
        response = client.get(f"/v1/artifact/{body['dissect_id']}/{artifact_id}")
        assert response.status_code == 410
        assert response.json()["error"]["code"] == "ARTIFACT_EXPIRED"

        # Sweeping removes the file but keeps the tombstone: still 410, not 404.
        assert app.state.store.sweep() >= 1
        assert client.get(f"/v1/artifact/{body['dissect_id']}/{artifact_id}").status_code == 410


def test_artifact_from_a_previous_process_life_is_404(settings: Settings, clock: FakeClock) -> None:
    """Test 19: unknown, not expired — the service remembers only within one process."""
    with TestClient(create_app(settings, clock=clock)) as first:
        body = dissect(first)
    artifact_id = _eml_id(body)

    # A second instance over the same directory: the files are there, the index is not.
    with TestClient(create_app(settings, clock=clock)) as second:
        response = second.get(f"/v1/artifact/{body['dissect_id']}/{artifact_id}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ARTIFACT_NOT_FOUND"


def test_failed_artifact_write_still_dissects(tmp_path: Path, clock: FakeClock) -> None:
    """Test 31: a store failure is an environment failure, not a property of the message."""
    blocked = tmp_path / "blocked"
    blocked.write_bytes(b"not a directory")
    settings = Settings(_env_file=None, artifact_dir=str(blocked))
    with TestClient(create_app(settings, clock=clock)) as client:
        body = dissect(client)
    assert body["ok"] is True
    assert body["artifacts"] == []
    assert "artifact_store_failed" in body["flags"]
    assert body["messages"][0]["headers"]  # the rest of the answer is intact
