import json
import logging
import asyncio
import base64
import re
import hashlib
import traceback
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.security.base import ScanStatus, SecurityResult
from app.security.pii_scanner import PIIScanner
from app.security.injection_scanner import InjectionScanner
from app.security.llm_scanner import LLMGuardScanner
from app.security.input_validator import InputValidator
from app.core.redis_client import redis_client
from app.models.security import SecurityLog, BlacklistedIP

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("Manager")

MAX_CONTEXT_LEN = 1000
LLM_TIMEOUT = 10.0
BAN_THRESHOLD = 5
CACHE_TTL = 86400

class SecurityPipeline:
    def __init__(self):
        self.validator = InputValidator()
        self.pii = PIIScanner()
        self.injection = InjectionScanner()
        self.llm = LLMGuardScanner()
        self.PIPELINE_VERSION = "v18_NO_BLEEDING"
        self.MODE = "strict"

    def _generate_cache_key(self, text: str) -> str:
        clean_text = text.strip()
        hash_object = hashlib.md5(clean_text.encode('utf-8'))
        return f"cache:response:{hash_object.hexdigest()}"

    async def check_rate_limits(self, user_id: int, ip: str) -> bool:
        if not redis_client: return True
        try:
            ip_key = f"ratelimit:manager:ip:{ip}"
            pipe = redis_client.pipeline()
            pipe.incr(ip_key)
            pipe.expire(ip_key, 60)
            results = await pipe.execute()
            if results[0] > 1000: return False
        except Exception:
            return True
        return True

    async def get_combined_context(self, user_id: int, current_text: str, ip: str) -> str:
        if not redis_client: return current_text
        try:
            context_key = f"context:last_msg:{user_id}:{ip}"
            last_msg = await redis_client.get(context_key)
            await redis_client.set(context_key, current_text[-MAX_CONTEXT_LEN:], ex=300)
            if last_msg:
                if isinstance(last_msg, bytes):
                    last_msg = last_msg.decode('utf-8')
                return f"{last_msg[-MAX_CONTEXT_LEN:]}\n{current_text}"
        except Exception:
            pass
        return current_text

    def _safe_log_dict(self, res):
        return {
            "scanner": res.scanner_name,
            "status": str(res.status.value) if hasattr(res.status, 'value') else str(res.status),
            "risk": (res.metadata or {}).get("risk_score", 0)
        }

    async def run(self, text: str, user_id: int, ip: str, db: AsyncSession):
        trace = []
        try:
            if redis_client:
                scoped_ban_key = f"banned:user:{user_id}:ip:{ip}"
                if await redis_client.get(scoped_ban_key):
                    return {
                        "allowed": False, "status": "BANNED",
                        "block_reason": "Access Denied: Your IP is banned for this API Key.",
                        "final_text": text, "trace": []
                    }

                cache_key = self._generate_cache_key(text)
                cached_response = await redis_client.get(cache_key)

                if cached_response:
                    trace.append({"scanner": "RedisCache", "status": "HIT", "risk": 0.0})
                    if isinstance(cached_response, bytes):
                        cached_response = cached_response.decode('utf-8')

                    cache_res = SecurityResult(
                        status=ScanStatus.ALLOWED,
                        scanner_name="RedisCache",
                        message="Clean (Cache Hit)",
                        sanitized_text=cached_response
                    )
                    return await self._finalize(cache_res, trace, user_id, ip, db)

            if not await self.check_rate_limits(user_id, ip):
                return {
                    "allowed": False, "status": "BLOCKED",
                    "reason": "Rate Limit", "block_reason": "Rate Limit Exceeded",
                    "final_text": text, "trace": []
                }

            res_val = await self.validator.scan(text)
            trace.append(self._safe_log_dict(res_val))
            if res_val.status == ScanStatus.BLOCKED:
                return await self._finalize(res_val, trace, user_id, ip, db)

            res_pii = await self.pii.scan(text)
            trace.append(self._safe_log_dict(res_pii))

            clean_text = res_pii.sanitized_text

            combined_text = await self.get_combined_context(user_id, clean_text, ip)
            res_inj = await self.injection.scan(combined_text)
            trace.append(self._safe_log_dict(res_inj))

            res_inj.sanitized_text = clean_text

            if (res_inj.metadata or {}).get("risk_score", 0) >= 1.0:
                return await self._finalize(res_inj, trace, user_id, ip, db)

            try:
                res_llm = await asyncio.wait_for(self.llm.scan(clean_text), timeout=LLM_TIMEOUT)
                trace.append(self._safe_log_dict(res_llm))

                res_llm.sanitized_text = clean_text

                if res_llm.status == ScanStatus.ERROR:
                    return {
                        "allowed": False, "status": "BLOCKED", "block_reason": "Security Check Failed (LLM Error)",
                        "final_text": clean_text, "trace": trace
                    }

                llm_score = (res_llm.metadata or {}).get("risk_score", 0)
                inj_risk = (res_inj.metadata or {}).get("risk_score", 0)

                if inj_risk >= 0.5 and llm_score >= 0.6:
                    res_llm.status = ScanStatus.BLOCKED
                    res_llm.message = "Combined Risk Detected"
                    return await self._finalize(res_llm, trace, user_id, ip, db)

                if res_llm.status == ScanStatus.BLOCKED:
                    return await self._finalize(res_llm, trace, user_id, ip, db)

            except asyncio.TimeoutError:
                return {"allowed": False, "status": "BLOCKED", "block_reason": "Security Check Timeout", "trace": trace}
            except Exception:
                pass

            if redis_client:
                await redis_client.set(cache_key, clean_text, ex=CACHE_TTL)

            success = SecurityResult(
                status=ScanStatus.ALLOWED,
                scanner_name="System",
                message="Clean",
                sanitized_text=clean_text
            )
            return await self._finalize(success, trace, user_id, ip, db)

        except Exception as e:
            traceback.print_exc()
            return {"allowed": False, "status": "BLOCKED", "block_reason": "System Error", "trace": trace}

    async def _finalize(self, res, trace, uid, ip, db):
        is_allowed = res.status != ScanStatus.BLOCKED
        if db:
            try:
                log = SecurityLog(
                    user_id=uid, client_ip=ip, endpoint="chat/secure",
                    request_text=res.sanitized_text, sanitized_text=res.sanitized_text,
                    scanner_name=res.scanner_name if not is_allowed else "System",
                    status=res.status,
                    risk_score=(res.metadata or {}).get("risk_score", 0.0),
                    metadata_log={"trace": trace, "original_msg": res.message}
                )
                db.add(log)
                await db.commit()
            except Exception:
                pass

        if not is_allowed:
            STRIKE_POINT = 1
            await handle_violation(db, uid, ip, res.message, STRIKE_POINT)
            return {"allowed": False, "status": "BLOCKED", "block_reason": res.message, "trace": trace,
                    "final_text": res.sanitized_text}

        return {"allowed": True, "status": "ALLOWED", "final_text": res.sanitized_text, "trace": trace}

async def handle_violation(db: AsyncSession, user_id: int, ip: str, reason: str, severity: int):
    if not redis_client: return
    try:
        violation_key = f"violation:user:{user_id}:ip:{ip}"
        ip_score = await redis_client.incrby(violation_key, severity)
        await redis_client.expire(violation_key, 3600)

        if ip_score >= BAN_THRESHOLD:
            ban_key = f"banned:user:{user_id}:ip:{ip}"
            await redis_client.set(ban_key, "permanent")
            try:
                stmt = select(BlacklistedIP).where(
                    (BlacklistedIP.ip_address == ip) &
                    (BlacklistedIP.user_id == user_id)
                )
                existing = await db.execute(stmt)
                if not existing.scalars().first():
                    new_ban = BlacklistedIP(
                        user_id=user_id,
                        ip_address=ip,
                        reason=f"Auto-Ban: 5 Strikes"
                    )
                    db.add(new_ban)
                    await db.commit()
            except Exception:
                pass
    except Exception:
        pass
