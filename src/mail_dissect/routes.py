"""The three endpoints (SPEC §4)."""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse

from . import __version__
from .artifacts import Lookup, content_disposition, valid_id
from .errors import AppError, new_dissect_id
from .headers import header_map
from .intake import boundary_of, extract_form_field, looks_like_message
from .jsonlog import log_event
from .models import (
    ArtifactOut,
    DissectResponse,
    HealthOut,
    MessageOut,
    RegistryVersionsOut,
    SourceHashes,
    scrub_surrogates,
)

router = APIRouter(prefix="/v1")


async def _read_body(request: Request, limit: int, dissect_id: str) -> bytes:
    """Read the request body, refusing oversize input before it is buffered (SPEC §15)."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise AppError("TOO_LARGE", f"message exceeds {limit} bytes", dissect_id)
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise AppError("TOO_LARGE", f"message exceeds {limit} bytes", dissect_id)
        chunks.append(chunk)
    return b"".join(chunks)


def _message_bytes(body: bytes, content_type: str) -> bytes | None:
    """Both channels are equal; the bytes must be identical through either one."""
    if content_type.lower().startswith("multipart/form-data"):
        boundary = boundary_of(content_type)
        if boundary is None:
            return None
        return extract_form_field(body, boundary)
    return body


@router.post("/dissect")
async def dissect(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    store = request.app.state.store
    clock = request.app.state.clock
    started = clock()
    # Minted before anything can fail: the envelope carries it on failure too, and without it
    # a consumer cannot correlate the error with the request (SPEC §16).
    dissect_id = new_dissect_id()

    body = await _read_body(request, settings.max_message_bytes, dissect_id)
    raw = _message_bytes(body, request.headers.get("content-type", ""))
    if not raw:
        raise AppError("BAD_REQUEST", "no message on input", dissect_id)
    if not looks_like_message(raw):
        # The one structural boundary: everything that falls apart after it is
        # `malformed_mime`, not an error (SPEC §15).
        raise AppError(
            "UNPARSABLE", "input has no header line before the first empty line", dissect_id
        )

    flags: list[Any] = []
    headers = header_map(raw)
    scrubbed: dict[str, list[str]] = {}
    changed = False
    for name, values in headers.items():
        cleaned = []
        for value in values:
            safe, was_changed = scrub_surrogates(value)
            changed = changed or was_changed
            cleaned.append(safe)
        scrubbed[name] = cleaned
    if changed:
        # [D20]: the returned string is no longer what stood in the material, so say so.
        flags.append("encoding_fallback")

    header_block = raw.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    artifacts = []
    # [D12]: the eml artifact carries the input bytes, never a reconstruction.
    for kind, payload, name in (
        ("eml", raw, "message.eml"),
        ("headers", header_block, "headers.txt"),
    ):
        ref = store.put(dissect_id, kind, payload, message_index=0, filename=name)
        if ref is None:
            if "artifact_store_failed" not in flags:
                flags.append("artifact_store_failed")
            continue
        artifacts.append(ref)

    response = DissectResponse(
        dissect_id=dissect_id,
        source=SourceHashes(
            size=len(raw),
            md5=hashlib.md5(raw, usedforsecurity=False).hexdigest(),
            sha1=hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
            sha256=hashlib.sha256(raw).hexdigest(),
        ),
        messages=[MessageOut(index=0, depth=0, headers=scrubbed)],
        artifacts=[ArtifactOut(**dataclasses.asdict(ref)) for ref in artifacts],
        flags=flags,
    )
    log_event(
        "dissect",
        dissect_id=dissect_id,
        size=len(raw),
        messages=len(response.messages),
        flags=flags,
        duration_ms=round((clock() - started) * 1000, 1),
    )
    return JSONResponse(content=response.model_dump())


@router.get("/artifact/{dissect_id}/{artifact_id}")
async def artifact(dissect_id: str, artifact_id: str, request: Request) -> FileResponse:
    """The only place hostile material returns to a browser, so nothing is echoed (SPEC §13.3)."""
    store = request.app.state.store
    status, record = store.lookup(dissect_id, artifact_id)
    if status is Lookup.EXPIRED:
        raise AppError("ARTIFACT_EXPIRED", "artifact has expired", dissect_id)
    if status is not Lookup.FOUND or record is None:
        raise AppError("ARTIFACT_NOT_FOUND", "no such artifact", dissect_id)
    return FileResponse(
        record.path,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": content_disposition(record.filename),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/artifact/{dissect_id}")
async def artifact_listing(dissect_id: str) -> JSONResponse:
    """There is no listing: one identifier must not be enough to derive the rest (SPEC §4)."""
    raise AppError(
        "ARTIFACT_NOT_FOUND",
        "artifacts are not listable",
        dissect_id if valid_id(dissect_id) else None,
    )


@router.get("/health")
async def health(request: Request) -> HealthOut:
    """200 whenever the service is alive, also when the optional tools do not answer."""
    app = request.app
    tools, age = await app.state.probes.states()
    versions = app.state.registries.versions
    return HealthOut(
        ok=True,
        version=__version__,
        uptime_seconds=max(0, int(app.state.clock() - app.state.started_at)),
        tools=tools,
        tools_checked_age_seconds=age,
        registries=RegistryVersionsOut(
            public_suffix_list=versions.public_suffix_list,
            file_extensions=versions.file_extensions,
        ),
    )
