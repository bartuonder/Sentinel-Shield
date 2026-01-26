from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.config import settings
from app.core.database import engine, Base
from app.core.middleware import SecurityMiddleware
from app.api.v1.endpoints import auth, chat, dashboard
from app.models.user import User
from app.models.security import SecurityLog

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "=" * 50)
    print("SENTINEL SHIELD BAŞLATILIYOR...")
    print(f"Modeller Yüklendi: {User.__tablename__}, {SecurityLog.__tablename__}")
    print("Veritabanı Tabloları Kontrol Ediliyor...")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("Veritabanı Hazır!")
    print("=" * 50 + "\n")

    yield
    print("Kapatılıyor...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

app.add_middleware(SecurityMiddleware)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(chat.router, prefix="/api/v1/chat", tags=["AI Chat"])

app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])


@app.get("/")
def root():
    return {"message": "Sentinel Shield Online"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}