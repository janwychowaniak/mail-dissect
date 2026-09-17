"""The optional tools: their states, and how `/v1/health` learns them (SPEC §14).

Both dependencies are soft. What is missing without each of them shows up in `tools{}`, and
one field carries the heaviest outcome of however many calls a dissection made, because a
partial success reported as a full one would be a silent failure.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

import httpx

from .models import ToolsOut, ToolState

# The heaviest outcome wins [D5]. A hard failure says more about a tool than one slow call.
_SEVERITY: dict[ToolState, int] = {
    "disabled": 0,
    "skipped": 1,
    "ok": 2,
    "timeout": 3,
    "down": 4,
}


class ToolTally:
    """Collects one tool's per-call outcomes within a single dissection."""

    __slots__ = ("_base", "_outcomes")

    def __init__(self, configured: bool) -> None:
        self._base: ToolState = "skipped" if configured else "disabled"
        self._outcomes: list[ToolState] = []

    def record(self, state: ToolState) -> None:
        self._outcomes.append(state)

    @property
    def state(self) -> ToolState:
        if not self._outcomes:
            return self._base
        return max(self._outcomes, key=lambda outcome: _SEVERITY[outcome])


class ToolProbes:
    """`/v1/health`'s view of the tools: probed on demand, behind a short cache [D6].

    Probing on every call would turn health into a traffic amplifier and let a hanging
    dependency lengthen the health response — which is how a restart mechanism ends up
    killing a working service for someone else's problem. A `disabled` tool is never probed,
    and a dissection never reads this cache: its states come from its own calls.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        tika_url: str,
        screenshot_url: str,
        *,
        timeout_seconds: float,
        cache_ttl_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._tika_url = tika_url
        self._screenshot_url = screenshot_url
        self._timeout = timeout_seconds
        self._ttl = cache_ttl_seconds
        self._clock = clock
        self._lock = asyncio.Lock()
        self._states = ToolsOut()
        self._checked_at: float | None = None

    @property
    def any_configured(self) -> bool:
        return bool(self._tika_url or self._screenshot_url)

    async def states(self) -> tuple[ToolsOut, int | None]:
        """Current states and the age of the measurement, or None when nothing is configured."""
        if not self.any_configured:
            return ToolsOut(tika="disabled", renderer="disabled"), None
        async with self._lock:
            now = self._clock()
            if self._checked_at is None or now - self._checked_at >= self._ttl:
                tika, renderer = await asyncio.gather(
                    self._probe(self._tika_url), self._probe(self._screenshot_url)
                )
                self._states = ToolsOut(tika=tika, renderer=renderer)
                self._checked_at = now
            age = int(self._clock() - self._checked_at)
        return self._states, age

    async def _probe(self, url: str) -> ToolState:
        if not url:
            return "disabled"
        try:
            response = await self._client.get(url, timeout=self._timeout)
        except httpx.TimeoutException:
            return "timeout"
        except httpx.HTTPError:
            return "down"
        # A POST-only route answering 405 is a live tool; only a server-side failure is `down`.
        return "down" if response.status_code >= 500 else "ok"
