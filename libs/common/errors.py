"""
Project-wide error convention.

AppError is the base for all deliberate, expected failures (validation
errors, invalid config, dependency unavailable, etc). Each has a stable
`code` and a client-safe `message`. `to_error_payload` renders the exact
shape required by the cahier des charges §76:

    {"error": "INVALID_EVENT", "message": "...", "event_id": "evt-123"}

Unexpected exceptions are never rendered with their stack trace to a
client; the caller logs the full traceback and returns a generic
INTERNAL_ERROR payload instead.
"""
from __future__ import annotations

from typing import Any, Optional


class AppError(Exception):
    code: str = "APP_ERROR"
    http_status: int = 400

    def __init__(self, message: str, *, event_id: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.event_id = event_id
        self.details = details or {}


class ValidationError(AppError):
    code = "INVALID_EVENT"
    http_status = 422


class ConfigurationError(AppError):
    code = "INVALID_CONFIGURATION"
    http_status = 500


class DependencyUnavailableError(AppError):
    code = "DEPENDENCY_UNAVAILABLE"
    http_status = 503


def to_error_payload(exc: AppError) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": exc.code, "message": exc.message}
    if exc.event_id is not None:
        payload["event_id"] = exc.event_id
    if exc.details:
        payload["details"] = exc.details
    return payload
