from fastapi import FastAPI
from app.core.config import settings
from app.core.database import engine, Base
from app.models import user
from app.api.v1.endpoints import auth, chat
from app.core.middleware import SecurityMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

app.add_middleware(SecurityMiddleware)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(chat.router, prefix="/api/v1/chat", tags=["AI Chat"])

@app.get("/")
def root():
    return {
        "message": "Sentinel Shield System Online",
        "docs": "Go to /docs for Swagger UI"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "core_systems": "active"}