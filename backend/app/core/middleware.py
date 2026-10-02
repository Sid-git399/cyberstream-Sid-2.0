import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from common.logging_utils import set_correlation_id


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Accepts an inbound X-Correlation-ID (useful when the frontend or another
    service already generated one) or mints a new UUID4. Every log line
    emitted while handling this request carries it (see common.logging_utils),
    and it's echoed back in the response header for the caller to correlate.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        set_correlation_id(correlation_id)
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
