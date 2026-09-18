"""The whole-dissection budget, as an object `[D10]`.

`asyncio.timeout` cancels an await; it cannot interrupt parsing running inside a worker
thread. So the budget is an explicit deadline, checked at the boundaries between units of
work — a message, an attachment, a single dependency call — and the service stops before the
next unit rather than in the middle of one. Without that, `truncated` (test 54) is not merely
imprecise but unimplementable.

The clock is injected so a test can state the passage of time instead of sleeping.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class Deadline:
    __slots__ = ("_clock", "_expires_at")

    def __init__(self, seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._expires_at = clock() + seconds

    def remaining(self) -> float:
        return max(0.0, self._expires_at - self._clock())

    def expired(self) -> bool:
        return self._clock() >= self._expires_at

    def budget(self, cap: float) -> float:
        """A dependency's own limit, never longer than what is left of the whole."""
        return min(cap, self.remaining())
