import os
import redis.asyncio as redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")

if not REDIS_URL:
    print("HATA: .env dosyasında REDIS_URL bulunamadı!")
    redis_client = None

else:
    try:
        redis_client = redis.from_url(
            REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            ssl_cert_reqs=None,
            socket_timeout=5,
            socket_connect_timeout=5,
            health_check_interval=30
        )
        print("Redis İstemcisi Başlatıldı (Async Mode).")

    except Exception as e:
        print(f"Redis Başlatma Hatası: {e}")
        redis_client = None

def get_redis_client():
    return redis_client