from fastapi import FastAPI
from app.core.config import settings
from app.core.database import engine, Base
from app.models import user
from app.api.v1.endpoints import auth

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

app.include_router(auth.router, prefix="/api/v1", tags=["auth"])

@app.get("/")
def root():
    return {
        "message": "Sentinel Shield System Online",
        "docs": "Go to /docs for Swagger UI"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "core_systems": "active"}