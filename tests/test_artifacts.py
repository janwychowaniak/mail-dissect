"""The artifact store and its endpoint: SPEC §13. Cases 14, 18, 19, 31, 55, 57."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest
from conftest import SIMPLE, FakeClock, dissect
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.artifacts import (
    ArtifactRef,
    ArtifactStore,
    Lookup,
    content_disposition,
    new_id,
    sanitise_filename,
)
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


def test_a_write_during_a_sweep_does_not_break_it(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A put runs in a dissection's worker thread, and a sweep in another one.

    The sweep is held in the middle of its pass over the index while a put from another
    thread adds to it. Without the store's lock the entry lands inside the pass, and the
    sweep raises `RuntimeError: dictionary changed size during iteration`.
    """
    store = ArtifactStore(tmp_path, ttl_seconds=10, clock=clock)
    old_dissect = new_id()
    old = store.put(old_dissect, "eml", b"old", message_index=0)
    assert old is not None
    clock.advance(11)

    in_sweep, release = threading.Event(), threading.Event()
    unlink = Path.unlink

    def held_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
        if self.name == old.artifact_id:
            in_sweep.set()
            release.wait(10)
        unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", held_unlink)
    errors: list[Exception] = []

    def sweep() -> None:
        try:
            store.sweep()
        except Exception as exc:
            errors.append(exc)

    sweeper = threading.Thread(target=sweep)
    sweeper.start()
    assert in_sweep.wait(10), "the sweep never reached the expired artifact"
    new_dissect = new_id()
    written: list[ArtifactRef | None] = []
    writer = threading.Thread(
        target=lambda: written.append(store.put(new_dissect, "eml", b"new", message_index=0))
    )
    writer.start()
    writer.join(0.5)  # without the lock, the put is done by now, inside the sweep's pass
    release.set()
    sweeper.join(10)
    writer.join(10)

    assert errors == []
    assert written[0] is not None
    assert store.lookup(old_dissect, old.artifact_id)[0] is Lookup.EXPIRED
    assert store.lookup(new_dissect, written[0].artifact_id)[0] is Lookup.FOUND


def test_a_sweep_leaves_the_directory_a_write_is_filling(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dissection that outlives `ARTIFACT_TTL_SECONDS` writes beside its swept artifacts.

    Its first artifact expires and is swept while it is still writing the next one into the
    same directory. The sweep removes a directory it finds empty, and the put has made it
    and not yet written into it. Without the lock covering the write, the directory goes and
    the write fails, which reads as `artifact_store_failed` on a store with nothing wrong.
    """
    store = ArtifactStore(tmp_path, ttl_seconds=10, clock=clock)
    dissect_id = new_id()
    assert store.put(dissect_id, "eml", b"old", message_index=0) is not None
    clock.advance(11)

    writing, proceed = threading.Event(), threading.Event()
    write_bytes = Path.write_bytes

    def held_write(self: Path, data: Any) -> int:
        if data == b"new":
            writing.set()
            proceed.wait(10)
        return write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", held_write)
    written: list[ArtifactRef | None] = []
    writer = threading.Thread(
        target=lambda: written.append(store.put(dissect_id, "eml", b"new", message_index=0))
    )
    writer.start()
    assert writing.wait(10), "the put never reached its write"
    sweeper = threading.Thread(target=store.sweep)
    sweeper.start()
    sweeper.join(0.5)  # without the lock, the sweep has removed the directory by now
    proceed.set()
    writer.join(10)
    sweeper.join(10)

    assert written[0] is not None
    assert store.lookup(dissect_id, written[0].artifact_id)[0] is Lookup.FOUND
