from __future__ import annotations

import time
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.common import utc_now


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
        request.state.request_id = request_id

        start = time.time()
        response = await call_next(request)
        duration_ms = round((time.time() - start) * 1000, 2)

        response.headers["X-Request-Id"] = request_id

        print(
            {
                "type": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "utc": utc_now(),
            }
        )

        return response
