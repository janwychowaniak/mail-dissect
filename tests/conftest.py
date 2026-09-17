"""Shared fixtures. The default suite is offline and must stay that way (SPEC §18)."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.settings import Settings


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """SPEC §2: a mock that misses must never turn into a real connection.

    This is one of the two independent ways test 12 is checked; the other is a container run
    with no network at all, which is the only honest test of the deployment claim.
    """
    if request.node.get_closest_marker("live"):
        return

    def _blocked(self: socket.socket, *args: object) -> None:
        raise AssertionError("an offline test attempted a real network connection (SPEC §2)")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


class FakeClock:
    """A monotonic clock the test moves by hand, so no test ever sleeps."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # _env_file=None so a developer's own .env never leaks into the suite.
    return Settings(_env_file=None, artifact_dir=str(tmp_path / "artifacts"))


@pytest.fixture
def client(settings: Settings, clock: FakeClock) -> Iterator[TestClient]:
    with TestClient(create_app(settings, clock=clock)) as test_client:
        yield test_client


SIMPLE = b"From: sender@example.com\r\nSubject: hello\r\n\r\nbody text\r\n"


def dissect(client: TestClient, raw: bytes = SIMPLE) -> dict:
    """POST a message through the raw-bytes channel and return the parsed response."""
    response = client.post("/v1/dissect", content=raw, headers={"content-type": "message/rfc822"})
    assert response.status_code == 200, response.text
    return response.json()
