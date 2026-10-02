import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from common.errors import AppError, to_error_payload

logger = logging.getLogger("backend")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        logger.warning(
            "handled application error",
            extra={"event_id": exc.event_id} if exc.event_id else None,
        )
        return JSONResponse(status_code=exc.http_status, content=to_error_payload(exc))

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Full traceback goes to the logs only; the client never sees internals.
        logger.exception("unhandled exception while processing request")
        return JSONResponse(
            status_code=500,
            content={"error": "INTERNAL_ERROR", "message": "An unexpected error occurred."},
        )
