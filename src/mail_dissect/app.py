"""The application factory.

Settings are built eagerly here, so a configuration error kills the process before uvicorn
binds rather than surfacing later as odd behaviour (SPEC §19). The registries are loaded and
verified at the same moment, for the same reason: a service running on a registry that is not
the one it reports would make `/v1/health` a lie.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI

from . import __version__
from .artifacts import ArtifactStore
from .errors import register_error_handlers
from .jsonlog import configure_logging, log_event
from .registries import Registries
from .routes import router
from .settings import Settings

SWEEP_INTERVAL_SECONDS = 60.0


def create_app(
    settings: Settings | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> FastAPI:
    """Build the app. `transport` and `clock` exist so tests need neither sockets nor sleep."""
    configure_logging()
    resolved = settings or Settings()
    registries = Registries.load()
    store = ArtifactStore(
        Path(resolved.artifact_dir), ttl_seconds=resolved.artifact_ttl_seconds, clock=clock
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # trust_env=False: a stray proxy variable must not become an egress path (SPEC §2).
        client = httpx.AsyncClient(transport=transport, trust_env=False)
        app.state.client = client
        app.state.probes = _build_probes(client, resolved, clock)
        sweeper = asyncio.create_task(_sweep_forever(store))
        log_event(
            "startup",
            version=__version__,
            public_suffix_list=registries.versions.public_suffix_list,
            file_extensions=registries.versions.file_extensions,
            extensions=registries.extension_count,
            tika=bool(resolved.tika_url),
            renderer=bool(resolved.screenshot_url),
        )
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            await client.aclose()

    app = FastAPI(
        title="mail-dissect",
        version=__version__,
        lifespan=lifespan,
        redirect_slashes=False,
        docs_url=None,
        redoc_url=None,
    )
    app.state.settings = resolved
    app.state.registries = registries
    app.state.store = store
    app.state.started_at = clock()
    register_error_handlers(app)
    app.include_router(router)
    return app


def _build_probes(
    client: httpx.AsyncClient, settings: Settings, clock: Callable[[], float]
) -> object:
    from .tools import ToolProbes

    return ToolProbes(
        client,
        settings.tika_url,
        settings.screenshot_url,
        timeout_seconds=settings.health_probe_timeout_seconds,
        cache_ttl_seconds=settings.health_cache_ttl_seconds,
        clock=clock,
    )


async def _sweep_forever(store: ArtifactStore) -> None:
    """Delete expired artifacts in the background; tombstones stay in the index (SPEC §13.4)."""
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        removed = store.sweep()
        if removed:
            log_event("artifacts_swept", removed=removed)
