"""The single error envelope and its six codes (SPEC §16).

`dissect_id` is present on failure too: without it a consumer cannot correlate the error with
the request. It is safe to return — a download needs both identifiers, so on its own it opens
nothing (SPEC §4).
"""

from __future__ import annotations

import secrets
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .jsonlog import log_event

ErrorCode = Literal[
    "BAD_REQUEST",
    "TOO_LARGE",
    "UNPARSABLE",
    "ARTIFACT_NOT_FOUND",
    "ARTIFACT_EXPIRED",
    "INTERNAL",
]

STATUS: dict[str, int] = {
    "BAD_REQUEST": 400,
    "TOO_LARGE": 413,
    "UNPARSABLE": 422,
    "ARTIFACT_NOT_FOUND": 404,
    "ARTIFACT_EXPIRED": 410,
    "INTERNAL": 500,
}


def new_dissect_id() -> str:
    """128 bits from a cryptographic generator (SPEC §4); never a counter or a timestamp."""
    return secrets.token_urlsafe(16)


class AppError(Exception):
    """An error with a place in the contract."""

    def __init__(self, code: ErrorCode, message: str, dissect_id: str | None = None) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message = message
        self.dissect_id = dissect_id


def envelope(code: str, message: str, dissect_id: str | None) -> dict[str, object]:
    return {"ok": False, "dissect_id": dissect_id, "error": {"code": code, "message": message}}


def _response(code: str, message: str, dissect_id: str | None) -> JSONResponse:
    return JSONResponse(status_code=STATUS[code], content=envelope(code, message, dissect_id))


async def _app_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)
    return _response(exc.code, exc.message, exc.dissect_id)


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    # Anything the router rejects is still shaped like our contract: a 404 for an unknown
    # path must not read differently from a 404 for an unknown artifact.
    code = {404: "ARTIFACT_NOT_FOUND", 413: "TOO_LARGE"}.get(exc.status_code, "BAD_REQUEST")
    if exc.status_code >= 500:
        code = "INTERNAL"
    dissect_id = request.path_params.get("dissect_id")
    return _response(code, str(exc.detail), dissect_id if isinstance(dissect_id, str) else None)


async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    # The fuzzer treats any 500 as a failure (SPEC §18); this handler exists so that a bug
    # still produces a contract-shaped answer instead of an ASGI traceback.
    log_event("unhandled_error", path=request.url.path, error=type(exc).__name__)
    return _response("INTERNAL", "internal error", None)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unhandled)
