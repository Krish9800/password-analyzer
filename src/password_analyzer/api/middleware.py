"""Security and privacy middleware ensuring zero-logging of credentials."""

import logging
import time
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("password_analyzer.api")


class PrivacyHeaderMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing secure response headers and privacy-safe access logging."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()

        response: Response = await call_next(request)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Log ONLY HTTP metadata: never inspect or log request bodies or parameters
        logger.info(
            "%s %s - Status: %d - Completed in %s ms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )

        # Enforce defensive HTTP security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

        return response
