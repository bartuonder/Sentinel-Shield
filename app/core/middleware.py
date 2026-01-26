import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from collections import defaultdict
from app.core.redis_client import redis_client

RATE_LIMIT_CONFIG = {
    "/api/v1/auth": 20,
    "/api/v1/chat": 120,
    "default": 200
}
RATE_LIMIT_DURATION = 60

request_counts = defaultdict(list)


class SecurityMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        path = request.url.path

        is_banned = redis_client.get(f"blacklist:{client_ip}")

        if is_banned:
            return JSONResponse(
                status_code=403,
                content={"error": "Access Denied. Your IP is banned permanently due to security violations."}
            )

        limit = RATE_LIMIT_CONFIG["default"]
        for route, config_limit in RATE_LIMIT_CONFIG.items():
            if path.startswith(route):
                limit = config_limit
                break

        identifier = client_ip

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer sk_live_"):
            api_key = auth_header.split(" ")[1]
            identifier = api_key

        current_time = time.time()
        request_history = request_counts[identifier]

        request_counts[identifier] = [t for t in request_history if current_time - t < RATE_LIMIT_DURATION]

        if len(request_counts[identifier]) >= limit:
            return self._generate_error_response(
                f"Rate limit exceeded. Max {limit} requests per minute. Identifier: {identifier[:10]}..."
            )

        request_counts[identifier].append(current_time)

        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)

        return response

    def _generate_error_response(self, message):
        return JSONResponse(status_code=429, content={"error": message})