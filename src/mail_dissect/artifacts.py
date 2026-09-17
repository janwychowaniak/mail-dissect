"""The ephemeral artifact store (SPEC §13).

Access rests entirely on identifiers being unguessable, so the identifiers come from a
cryptographic generator and there is no endpoint that lists them. The in-process index is
what makes 410 distinguishable from 404: an expired entry leaves a tombstone for the rest of
the process's life, while an identifier from a previous process life is simply unknown.

The store manages no space: no quota, no eviction, nothing deleted to make room. How much
space the machine has is the responsibility of whoever runs it.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import quote

from .jsonlog import log_event
from .models import ArtifactKind

ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_WHITESPACE = re.compile(r"\s+")
MAX_FILENAME_LENGTH = 100


def new_id() -> str:
    """22 URL-safe characters, 128 bits of entropy (SPEC §4)."""
    return secrets.token_urlsafe(16)


def valid_id(value: str) -> bool:
    """Shape check before anything touches the filesystem — this is the traversal defence."""
    return bool(ID_RE.match(value))


def sanitise_filename(name: str | None, fallback: str) -> str:
    """Make a sender-supplied name safe to put in a header (SPEC §13.3).

    The standard library does not strip path components for us (F4), and a CR or LF in a
    filename breaks the response headers apart, so this is not optional politeness.
    """
    if not name:
        return fallback
    cleaned = _CONTROL.sub("", name)
    cleaned = cleaned.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = re.sub(r"^[A-Za-z]:", "", cleaned)
    cleaned = _WHITESPACE.sub(" ", cleaned).strip(" .")
    if not cleaned or cleaned in {".", ".."}:
        return fallback
    if len(cleaned) > MAX_FILENAME_LENGTH:
        stem, dot, extension = cleaned.rpartition(".")
        if dot and len(extension) <= 10:
            keep = MAX_FILENAME_LENGTH - len(extension) - 1
            cleaned = f"{stem[:keep]}.{extension}"
        else:
            cleaned = cleaned[:MAX_FILENAME_LENGTH]
    return cleaned or fallback


def content_disposition(filename: str) -> str:
    """RFC 6266 with an ASCII fallback; never the sender's bytes verbatim."""
    ascii_name = "".join(c if 32 <= ord(c) < 127 and c not in '"\\' else "_" for c in filename)
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename, safe='')}"


class Lookup(Enum):
    FOUND = "found"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """What the response needs to describe a stored artifact."""

    artifact_id: str
    message_index: int
    part_index: int | None
    kind: ArtifactKind
    filename: str
    mime: str
    size: int
    sha256: str


@dataclass(slots=True)
class _Record:
    path: Path
    filename: str
    size: int
    expires_at: float
    expired: bool = False


class ArtifactStore:
    """Files under `root/<dissect_id>/<artifact_id>`, metadata in memory."""

    def __init__(
        self,
        root: Path,
        ttl_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._root = root
        self._ttl = ttl_seconds
        self._clock = clock
        self._index: dict[tuple[str, str], _Record] = {}

    @property
    def root(self) -> Path:
        return self._root

    def put(
        self,
        dissect_id: str,
        kind: ArtifactKind,
        data: bytes,
        *,
        message_index: int,
        part_index: int | None = None,
        filename: str = "artifact.bin",
        mime: str = "application/octet-stream",
    ) -> ArtifactRef | None:
        """Store bytes, or return None when the environment would not let us (SPEC §13.4).

        A failed write is not a failed dissection: the caller raises `artifact_store_failed`
        and keeps the rest of the answer, which is valuable on its own.
        """
        artifact_id = new_id()
        directory = self._root / dissect_id
        path = directory / artifact_id
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        except OSError as exc:
            log_event("artifact_store_failed", dissect_id=dissect_id, error=type(exc).__name__)
            return None
        safe_name = sanitise_filename(filename, f"{kind}.bin")
        self._index[(dissect_id, artifact_id)] = _Record(
            path=path,
            filename=safe_name,
            size=len(data),
            expires_at=self._clock() + self._ttl,
        )
        return ArtifactRef(
            artifact_id=artifact_id,
            message_index=message_index,
            part_index=part_index,
            kind=kind,
            filename=safe_name,
            mime=mime,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def lookup(self, dissect_id: str, artifact_id: str) -> tuple[Lookup, _Record | None]:
        """FOUND, EXPIRED (this process life) or UNKNOWN (anything else, SPEC §13.4)."""
        if not valid_id(dissect_id) or not valid_id(artifact_id):
            return Lookup.UNKNOWN, None
        record = self._index.get((dissect_id, artifact_id))
        if record is None:
            return Lookup.UNKNOWN, None
        if record.expired or self._clock() >= record.expires_at:
            return Lookup.EXPIRED, record
        if not record.path.exists():
            # The tmpfs was wiped under us. That is not "expired" — the consumer treats both
            # as normal cases, and calling it expired would claim knowledge we do not have.
            return Lookup.UNKNOWN, None
        return Lookup.FOUND, record

    def sweep(self) -> int:
        """Delete expired files, keep their tombstones. Returns how many were removed."""
        now = self._clock()
        removed = 0
        for record in self._index.values():
            if record.expired or now < record.expires_at:
                continue
            record.expired = True
            try:
                record.path.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass
            parent = record.path.parent
            try:
                next(parent.iterdir())
            except StopIteration:
                parent.rmdir()
            except OSError:
                pass
        return removed

    def dissect_ids(self) -> list[str]:
        """Only for tests and the sweeper's own bookkeeping; never exposed over HTTP."""
        return sorted({dissect_id for dissect_id, _ in self._index})
