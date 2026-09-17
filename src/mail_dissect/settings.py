"""Configuration, read from the environment only (SPEC §19).

Every limit in SPEC §15 is a field here, with the specified default, so the image starts
with no variable set. Settings are built eagerly in the app factory: a configuration error
must kill the process before the server binds, never surface later as odd behaviour.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_SOURCE_RE = re.compile(r"^(?:query:[^\s]+|path_segment:\d+)$")
_EXTENSION_RE = re.compile(r"^\.?[A-Za-z0-9][A-Za-z0-9+._-]{0,15}$")


class UnwrapperRule(BaseModel):
    """One declarative entry of the unwrapper table (SPEC §10).

    Regular expressions are deliberately not accepted: a declarative entry can be validated
    at startup and carried between deployments, a hand-written pattern can be neither.
    """

    model_config = {"extra": "forbid"}

    host_suffix: str = Field(min_length=1)
    source: str
    decoder: Literal["percent", "base64", "base64url", "none"]
    strip_prefix: str | None = None
    strip_suffix: str | None = None

    @field_validator("source")
    @classmethod
    def _known_source(cls, value: str) -> str:
        # A bad source is a silent misconfiguration: the wrapper would match and never
        # unwrap, which is indistinguishable from "this wrapper is irreversible" (SPEC §10).
        if not _SOURCE_RE.match(value):
            raise ValueError(
                "source must be 'query:<parameter>' or 'path_segment:<zero-based number>', "
                f"got {value!r}"
            )
        return value

    @field_validator("host_suffix")
    @classmethod
    def _plain_host_suffix(cls, value: str) -> str:
        if value.startswith("."):
            raise ValueError(
                f"host_suffix matches on a label boundary already; drop the dot: {value!r}"
            )
        return value.lower()


class Settings(BaseSettings):
    """Environment configuration. Field names are the lowercased variable names."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Limits (SPEC §15)
    max_message_bytes: int = Field(default=50 * 1024 * 1024, gt=0)
    max_attachment_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    max_nesting_depth: int = Field(default=5, ge=1)
    max_mime_parts: int = Field(default=500, ge=1)
    max_inline_body_bytes: int = Field(default=256 * 1024, ge=0)

    # Time budgets (SPEC §15) — three, not one
    dissect_timeout_seconds: float = Field(default=60.0, gt=0)
    tika_timeout_seconds: float = Field(default=20.0, gt=0)
    screenshot_timeout_seconds: float = Field(default=30.0, gt=0)
    health_probe_timeout_seconds: float = Field(default=2.0, gt=0)
    health_cache_ttl_seconds: float = Field(default=10.0, ge=0)

    # Artifact store (SPEC §13.4)
    artifact_ttl_seconds: float = Field(default=1800.0, gt=0)
    artifact_dir: str = "/tmp"

    # Optional tools (SPEC §14) — empty means `disabled`, not "broken"
    tika_url: str = ""
    screenshot_url: str = ""

    # The unwrapper table (SPEC §10). Empty by default: shipping a ready-made list would be
    # a choice about whose filters matter. Malformed JSON here stops the service (test 42).
    unwrappers: list[UnwrapperRule] = Field(default_factory=list)

    # Extensions the registry does not know, added by the deployment [D22]. Empty by default,
    # additive only: it never removes anything from mime-db. The registry is keyed by media
    # type, so formats without a registered one (`scr`, `hta`, `ps1`, …) are absent from it
    # (F13) — and a list of those shipped by us would be our point of view, which §2 forbids.
    # This is the same shape as UNWRAPPERS: we provide the mechanism, the deployment provides
    # the content, and what it provides is visible in /v1/health because it changes results.
    # NoDecode: without it pydantic-settings JSON-decodes the value at the source, before
    # any validator runs, and `scr,hta` is not JSON.
    extra_file_extensions: Annotated[list[str], NoDecode] = Field(default_factory=list)

    @field_validator("extra_file_extensions", mode="before")
    @classmethod
    def _split_extensions(cls, value: object) -> object:
        """Accept `scr,hta,ps1` and a JSON array alike.

        Comma-separated is what anyone types into an env file; the JSON form is what anyone
        assumes after seeing UNWRAPPERS one line above, and failing on it would be a trap of
        our own making.
        """
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text.startswith("["):
            try:
                return json.loads(text)
            except ValueError as exc:
                raise ValueError(f"looks like JSON but does not parse: {exc}") from exc
        return [item for item in (part.strip() for part in text.split(",")) if item]

    @field_validator("extra_file_extensions")
    @classmethod
    def _normalise_extensions(cls, value: list[str]) -> list[str]:
        normalised: list[str] = []
        for item in value:
            # A typo that silently never matches is the same failure mode as a bad unwrapper
            # source: it looks like "this deployment has nothing to add" (SPEC §10).
            if not _EXTENSION_RE.match(item):
                raise ValueError(f"{item!r} is not a file extension; write them as `scr,hta,ps1`")
            cleaned = item.lstrip(".").lower()
            if cleaned not in normalised:
                normalised.append(cleaned)
        return sorted(normalised)
