from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.future import select
from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.middleware import SecurityMiddleware
from app.api.v1.endpoints import auth, chat, dashboard
from app.models.user import User
from app.models.security import SecurityLog, BlacklistedIP
from app.core.redis_client import redis_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "=" * 50)
    print("SENTINEL SHIELD BASLATILIYOR...")
    print(f"Modeller Yuklendi: {User.__tablename__}, {SecurityLog.__tablename__}")
    print("Veritabani Tablolari Kontrol Ediliyor...")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("Veritabani Hazir!")

    print("Cache Warming Baslatiliyor (DB -> Redis)...")
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(BlacklistedIP))
            banned_ips = result.scalars().all()

        count = 0
        if redis_client:
            for ban in banned_ips:
                redis_key = f"banned:{ban.user_id}:{ban.ip_address}"
                reason = ban.reason or "Permanent Ban"

                await redis_client.set(redis_key, reason)
                count += 1
            print(f"Cache Warming Tamamlandi: {count} IP Redis'e yuklendi.")
        else:
            print("Redis baglantisi yok, Cache Warming atlandi.")

    except Exception as e:
        print(f"Cache Warming sirasinda hata olustu: {e}")

    print("=" * 50 + "\n")

    yield
    print("Kapatiliyor...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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