"""JSON-lines logging to stdout (SPEC §20).

No log files and no rotation: that is the container runtime's job. One event line per
dissection, and never any message content — nor an `artifact_id`, which is an access key
(SPEC §4). A filter enforces the second rule rather than trusting call sites to remember it.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_RESERVED = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__.keys() | {"message", "asctime"}
)

LOGGER_NAME = "mail_dissect"


class JsonFormatter(logging.Formatter):
    """One JSON object per line: timestamp, level, event, then structured fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED:
                payload[key] = value
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class NoArtifactIdFilter(logging.Filter):
    """Drop any field that would put an artifact identifier in the log (SPEC §4).

    A logged artifact identifier is a logged access key, and `dissect_id` alone opens
    nothing. Enforced here so that a future call site cannot leak one by accident.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key in list(record.__dict__):
            if "artifact_id" in key:
                record.__dict__[key] = "[redacted]"
        return True


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    """Install the JSON handler on our logger. Idempotent."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        handler.addFilter(NoArtifactIdFilter())
        logger.addHandler(handler)
    # The HTTP client must not log request URLs: they carry the tool addresses, and its
    # debug output is noise in a JSON-lines stream.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logger


def log_event(event: str, **fields: Any) -> None:
    logging.getLogger(LOGGER_NAME).info(event, extra=fields)
