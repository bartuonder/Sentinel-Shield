import time
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


class SecurityMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        path = request.url.path

        if path in ["/health", "/", "/docs", "/openapi.json"]:
            return await call_next(request)

        if redis_client:
            ip_ban_key = f"banned:ip:{client_ip}"
            is_ip_banned = await redis_client.get(ip_ban_key)
            if is_ip_banned:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access Denied",
                        "detail": "Your IP is permanently banned."
                    }
                )

        user = None
        identifier = f"ip:{client_ip}"

        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer sk_"):
            api_key = auth_header.split(" ")[1]

            async with AsyncSessionLocal() as db:
                result = await db.execute(select(User).where(User.api_key == api_key))
                user = result.scalar_one_or_none()

            if user:
                identifier = f"user:{user.id}"
                request.state.user = user

                if redis_client:
                    user_ban_key = f"banned:user:{user.id}"
                    is_user_banned = await redis_client.get(user_ban_key)
                    if is_user_banned:
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "Access Denied",
                                "detail": "Your Account is banned due to security violations."
                            }
                        )
            else:
                return JSONResponse(status_code=401, content={"error": "Invalid API Key"})

        limit = RATE_LIMIT_CONFIG.get(path, RATE_LIMIT_CONFIG["default"])
        if limit == RATE_LIMIT_CONFIG["default"]:
            for route, config_limit in RATE_LIMIT_CONFIG.items():
                if path.startswith(route):
                    limit = config_limit
                    break

        rate_key = f"rate_limit:{identifier}:{path}"

        if redis_client:
            try:
                current_count = await redis_client.incr(rate_key)

                if current_count == 1:
                    await redis_client.expire(rate_key, RATE_LIMIT_DURATION)

                if current_count > limit:
                    ttl = await redis_client.ttl(rate_key)
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "Rate limit exceeded",
                            "detail": f"Max {limit} requests per minute. Try again in {ttl} seconds."
                        }
                    )
            except Exception as e:
                print(f"[MIDDLEWARE] Redis Rate Limit Hatası: {e}")
                pass

        response = await call_next(request)
        return response