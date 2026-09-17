"""Health endpoint: SPEC §14.3, acceptance cases 36 and 61."""

from __future__ import annotations

import httpx
import pytest
from conftest import FakeClock
from fastapi.testclient import TestClient

from mail_dissect.app import create_app
from mail_dissect.settings import Settings


def test_health_reports_registry_versions_with_tools_disabled(client: TestClient) -> None:
    """Test 36: 200 with dependencies off, all fields present, registry versions exposed."""
    body = client.get("/v1/health").json()
    assert body["ok"] is True
    assert body["tools"] == {"tika": "disabled", "renderer": "disabled"}
    # No address configured means the tool does not exist for this deployment [D1], and
    # nothing was probed, so there is no measurement to date.
    assert body["tools_checked_age_seconds"] is None
    assert body["registries"]["public_suffix_list"].endswith("/bb3d3bb844f1")
    assert "+icann/" in body["registries"]["public_suffix_list"]  # [D21] names the section
    assert body["registries"]["file_extensions"].startswith("mime-db@")
    assert body["uptime_seconds"] == 0
    assert body["version"]


def test_uptime_is_measured_on_the_service_clock(client: TestClient, clock: FakeClock) -> None:
    """Uptime must come from the same clock the service was started on.

    Reading `time.monotonic()` here instead looked right on a developer machine and produced
    a negative uptime on a fresh CI runner, because the two clocks share no origin.
    """
    assert client.get("/v1/health").json()["uptime_seconds"] == 0
    clock.advance(125)
    assert client.get("/v1/health").json()["uptime_seconds"] == 125


def test_disabled_tools_are_never_probed(client: TestClient) -> None:
    """Test 61, first half: no addresses means no traffic at all.

    The autouse socket guard turns any real connection into a failure, so this passing is
    the assertion; `tools_checked_age_seconds` being null is the visible half of it.
    """
    for _ in range(3):
        assert client.get("/v1/health").json()["tools_checked_age_seconds"] is None


@pytest.mark.parametrize("status", [500, 503])
def test_unreachable_tools_are_down_and_health_is_still_200(
    settings: Settings, clock: FakeClock, status: int
) -> None:
    """Test 61, second half: a dead dependency is a poorer mode, never our failure."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(status)

    configured = settings.model_copy(
        update={"tika_url": "http://tika.invalid", "screenshot_url": "http://shot.invalid"}
    )
    app = create_app(configured, transport=httpx.MockTransport(handler), clock=clock)
    with TestClient(app) as client:
        body = client.get("/v1/health").json()
        assert body["ok"] is True
        assert body["tools"] == {"tika": "down", "renderer": "down"}
        assert body["tools_checked_age_seconds"] <= configured.health_cache_ttl_seconds
        assert len(calls) == 2

        # Test 61, third half: two calls inside the TTL probe once [D6].
        client.get("/v1/health")
        assert len(calls) == 2

        clock.advance(configured.health_cache_ttl_seconds + 1)
        client.get("/v1/health")
        assert len(calls) == 4


def test_timeout_is_not_down(settings: Settings, clock: FakeClock) -> None:
    """The two failures mean different things to a consumer, so they stay distinct."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    configured = settings.model_copy(update={"tika_url": "http://tika.invalid"})
    app = create_app(configured, transport=httpx.MockTransport(handler), clock=clock)
    with TestClient(app) as client:
        body = client.get("/v1/health").json()
        assert body["tools"]["tika"] == "timeout"
        assert body["tools"]["renderer"] == "disabled"
