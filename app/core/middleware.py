import time
from collections import defaultdict
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.future import select
from app.core.redis_client import redis_client
from app.core.database import AsyncSessionLocal
from app.models.user import User

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

        user = None
        identifier = client_ip
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer sk_"):
            api_key = auth_header.split(" ")[1]

            async with AsyncSessionLocal() as db:
                result = await db.execute(select(User).where(User.api_key == api_key))
                user = result.scalar_one_or_none()

            if user:
                identifier = api_key
                request.state.user = user

            else:
                return JSONResponse(status_code=401, content={"error": "Invalid API Key"})

        if user:
            ban_key = f"banned:{user.id}:{client_ip}"

            try:

                is_banned = await redis_client.get(ban_key)

                if is_banned:
                    print(f"🛑 [MIDDLEWARE] BAN YAKALANDI! Key: {ban_key} -> Value: {is_banned}")
                    return JSONResponse(
                        status_code=403,
                        content={"error": "KALICI BANLANDIN (Access Denied. Permanent Ban.)"}
                    )
                else:

                    pass

            except Exception as e:
                print(f"[MIDDLEWARE] Redis Hatası: {e}")

        # 3. RATE LIMITING
        limit = RATE_LIMIT_CONFIG.get(path, RATE_LIMIT_CONFIG["default"])
        if limit == RATE_LIMIT_CONFIG["default"]:
            for route, config_limit in RATE_LIMIT_CONFIG.items():
                if path.startswith(route):
                    limit = config_limit
                    break

        current_time = time.time()
        request_history = request_counts[identifier]
        request_counts[identifier] = [t for t in request_history if current_time - t < RATE_LIMIT_DURATION]

        if len(request_counts[identifier]) >= limit:
            return JSONResponse(
                status_code=429,
                content={"error": f"Rate limit exceeded. Max {limit} requests per minute."}
            )

        request_counts[identifier].append(current_time)

        response = await call_next(request)
        return response