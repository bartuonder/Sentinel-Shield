import os
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")

if not REDIS_URL:
    print("HATA: .env dosyasında REDIS_URL bulunamadı!")
else:
    print(f"Redis Bağlantısı deneniyor: {REDIS_URL[:15]}...")

try:

    redis_client = redis.from_url(
        REDIS_URL,
        decode_responses=True,
        ssl_cert_reqs=None,
        socket_timeout=5,
        socket_connect_timeout=5,
        health_check_interval=30
    )


    redis_client.ping()
    print("Redis Bağlantısı Başarılı! (Cloud - Upstash)")

except Exception as e:
    print(f"Redis Bağlantı Hatası: {e}")
    redis_client = None


def get_redis_client():
    return redis_client