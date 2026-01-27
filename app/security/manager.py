import hashlib
import json
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.security.base import BaseScanner, SecurityResult, ScanStatus
from app.security.pii_scanner import PIIScanner
from app.security.injection_scanner import InjectionScanner
from app.security.llm_scanner import LLMGuardScanner
from app.security.input_validator import InputValidator
from app.models.security import BlacklistedIP
from app.core.redis_client import redis_client

MAX_VIOLATIONS = 5
VIOLATION_TTL = 3600
CACHE_TTL = 86400


class SecurityPipeline:
    def __init__(self):
        self.scanners: List[BaseScanner] = [
            InputValidator(),
            PIIScanner(),
            InjectionScanner(),
            LLMGuardScanner()
        ]

    async def run(self, text: str, user_id: int = None) -> Dict[str, Any]:

        text_hash = hashlib.sha256(text.encode()).hexdigest()
        cache_key = f"scan_cache:{text_hash}"

        cached_result = await redis_client.get(cache_key)
        if cached_result:
            print("CACHE HIT: OpenAI'a gidilmedi, redis'ten döndü.")
            return json.loads(cached_result)

        current_text = text
        trace_logs = []
        final_status = ScanStatus.ALLOWED
        block_reason = None

        for scanner in self.scanners:
            result: SecurityResult = await scanner.scan(current_text)

            trace_logs.append({
                "scanner": result.scanner_name,
                "status": result.status,
                "message": result.message,
                "metadata": result.metadata
            })

            current_text = result.sanitized_text

            if result.status != ScanStatus.ALLOWED:
                final_status = result.status
                block_reason = f"[{result.scanner_name}] {result.message}"
                break

        response_data = {
            "allowed": final_status == ScanStatus.ALLOWED,
            "status": final_status,
            "final_text": current_text,
            "block_reason": block_reason,
            "trace": trace_logs
        }

        await redis_client.set(cache_key, json.dumps(response_data), ex=CACHE_TTL)

        return response_data


async def handle_violation(db: AsyncSession, user_id: int, ip_address: str, reason: str):

    violation_key = f"violation:{user_id}:{ip_address}"

    current_count = await redis_client.incr(violation_key)

    if current_count == 1:
        await redis_client.expire(violation_key, VIOLATION_TTL)

    print(f"İHLAL: {ip_address} (User ID: {user_id}) - Sayaç: {current_count}/{MAX_VIOLATIONS}")

    if current_count >= MAX_VIOLATIONS:
        print(f"LİMİT AŞILDI! {ip_address} kalıcı banlanıyor...")

        try:

            existing = await db.execute(
                select(BlacklistedIP).where(
                    (BlacklistedIP.ip_address == ip_address) &
                    (BlacklistedIP.user_id == user_id)
                )
            )
            if not existing.scalar_one_or_none():
                new_ban = BlacklistedIP(
                    user_id=user_id,
                    ip_address=ip_address,
                    reason=f"Limit aşıldı ({current_count} saldırı). Son sebep: {reason}"
                )
                db.add(new_ban)
                await db.commit()
        except Exception as e:
            print(f"DB Ban Hatası: {e}")
            await db.rollback()

        ban_key = f"banned:{user_id}:{ip_address}"
        await redis_client.set(ban_key, "true", ex=2592000)  # 30 Gün

        await redis_client.delete(violation_key)