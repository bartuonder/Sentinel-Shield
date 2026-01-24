import time
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict

RATE_LIMIT_DURATION = 60
MAX_REQUEST_PER_MINUTE = 20

request_counts = defaultdict(list)

class SecurityMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        start_time = time.time()
        client_ip = request.client.host
        current_time = time.time()
        request_history = request_counts[client_ip]
        request_counts[client_ip] = [t for t in request_history if current_time - t < RATE_LIMIT_DURATION]

        if len(request_counts[client_ip]) > MAX_REQUEST_PER_MINUTE:
            return self._generate_error_response("You are going too fast.")

        request_counts[client_ip].append(current_time)

        response = await call_next(request)

        process_time = time.time() - start_time

        response.headers["X-Process-Time"] = str(process_time)

        return response

    def _generate_error_response(self, message):

        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=429, content={"error": message})