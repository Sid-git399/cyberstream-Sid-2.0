"""
Project-wide structured logging convention.

Every service (backend, generator, streaming) calls configure_logging(...)
once at startup. Log records are emitted as single-line JSON with the
fields required by the cahier des charges §75: timestamp, service, level,
message, event_id, correlation_id. Passwords/secrets/tokens/credentials
must never be passed as log fields (see docs/logging.md).
"""
from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Optional

# correlation_id flows through a request/job without being threaded through
# every function signature. Backend middleware sets it per HTTP request;
# the generator/streaming set it per run or per batch.
_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default="-"
)


def set_correlation_id(value: str) -> None:
    _correlation_id.set(value)


def get_correlation_id() -> str:
    return _correlation_id.get()


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "service": self.service,
            "level": record.levelname,
            "message": record.getMessage(),
            "correlation_id": get_correlation_id(),
            "logger": record.name,
        }
        event_id = getattr(record, "event_id", None)
        if event_id is not None:
            payload["event_id"] = event_id
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(service: str, level: str = "INFO", stream=None) -> logging.Logger:
    """
    Logs go to stderr by default. This matters most for the generator CLI,
    which can write event data (NDJSON) to stdout - if logs also went to
    stdout they would interleave with and corrupt that data stream for
    anyone piping `generate` straight into a file or another process.
    Docker/Compose capture both stdout and stderr into the same log
    output, so this costs the backend nothing.

    Idempotent: safe to call more than once (e.g. once per test module)
    without stacking duplicate handlers.
    """
    root = logging.getLogger()
    root.setLevel(level.upper())

    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(stream=stream or sys.stderr)
    handler.setFormatter(JsonFormatter(service=service))
    root.addHandler(handler)

    return logging.getLogger(service)


def log_event(logger: logging.Logger, level: int, message: str, *, event_id: Optional[str] = None) -> None:
    logger.log(level, message, extra={"event_id": event_id} if event_id else None)
