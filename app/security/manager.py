import hashlib
import json
import logging
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from app.security.base import ScanStatus
from app.security.pii_scanner import PIIScanner
from app.security.injection_scanner import InjectionScanner
from app.security.llm_scanner import LLMGuardScanner
from app.security.input_validator import InputValidator
from app.core.redis_client import redis_client

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("Manager")

MAX_CONTEXT_LEN = 1000
MAX_HASH_LEN = 2000
LLM_TIMEOUT = 4.0

class SecurityPipeline:
    def __init__(self):
        self.validator = InputValidator()
        self.pii = PIIScanner()
        self.injection = InjectionScanner()
        self.llm = LLMGuardScanner()

        self.PIPELINE_VERSION = "v5_SAFE"
        self.MODE = "strict"
        self.BLOCK_ON_CRITICAL_PII = True

    async def check_rate_limits(self, user_id: int, ip: str) -> bool:
        user_key = f"ratelimit:user:{user_id}"
        ip_key = f"ratelimit:ip:{ip}"

        pipe = redis_client.pipeline()
        pipe.incr(user_key)
        pipe.expire(user_key, 60)
        pipe.incr(ip_key)
        pipe.expire(ip_key, 60)
        results = await pipe.execute()

        user_count = results[0]
        ip_count = results[2]

        if user_count > 20: return False
        if ip_count > 100: return False
        return True

    async def get_combined_context(self, user_id: int, current_text: str) -> str:
        context_key = f"context:last_msg:{user_id}"
        last_msg = await redis_client.get(context_key)

        await redis_client.set(context_key, current_text[-MAX_CONTEXT_LEN:], ex=300)

        if last_msg:
            return f"{last_msg[-MAX_CONTEXT_LEN:]}\n{current_text}"
        return current_text

    async def run(self, text: str, user_id: int, ip: str, db: AsyncSession):
        if await redis_client.get(f"banned:user:{user_id}") or await redis_client.get(f"banned:ip:{ip}"):
            return {"allowed": False, "status": "BANNED"}

        if "." in ip and ":" not in ip:
            subnet = ".".join(ip.split(".")[:3])
            if await redis_client.get(f"banned:subnet:{subnet}"):
                return {"allowed": False, "status": "BANNED"}

        if not await self.check_rate_limits(user_id, ip):
            return {"allowed": False, "status": "BLOCKED", "reason": "Rate Limit"}

        trace = []

        res_val = await self.validator.scan(text)
        trace.append(self._safe_log(res_val))
        if res_val.status == ScanStatus.BLOCKED:
            return await self._block(res_val, trace, user_id, ip, db)

        clean_text = res_val.sanitized_text

        combined_text = await self.get_combined_context(user_id, clean_text)

        hash_base = combined_text[:MAX_HASH_LEN]
        text_hash = hashlib.sha256(hash_base.encode()).hexdigest()
        cache_key = f"scan:{self.PIPELINE_VERSION}:{self.MODE}:{user_id}:{text_hash}"

        cached = await redis_client.get(cache_key)
        if cached: return json.loads(cached)

        res_inj = await self.injection.scan(combined_text)
        trace.append(self._safe_log(res_inj))

        inj_score = res_inj.metadata.get("risk_score", 0)
        if inj_score >= 1.0:
            return await self._block(res_inj, trace, user_id, ip, db)

        res_pii = await self.pii.scan(clean_text)
        trace.append(self._safe_log(res_pii))

        detected = res_pii.metadata.get("detected_types", [])

        if res_pii.metadata.get("hidden_pii"):
            return await self._block(res_pii, trace, user_id, ip, db)

        criticals = ["TR_TCKN", "TR_IBAN", "CREDIT_CARD", "TR_TCKN_HIDDEN"]
        if self.BLOCK_ON_CRITICAL_PII and any(d in criticals for d in detected):
            return {"allowed": False, "status": "BLOCKED", "block_reason": "Sensitive Data Policy"}

        llm_input_text = res_pii.sanitized_text

        try:
            res_llm = await asyncio.wait_for(self.llm.scan(llm_input_text), timeout=LLM_TIMEOUT)
        except asyncio.TimeoutError:
            return {"allowed": False, "status": "BLOCKED", "block_reason": "Security Check Timeout"}

        trace.append(self._safe_log(res_llm))

        if res_llm.status == ScanStatus.ERROR:
            return {"allowed": False, "status": "BLOCKED", "block_reason": "Security Check Failed"}

        llm_score = res_llm.metadata.get("risk_score", 0)
        threshold = 0.5 if self.MODE == "strict" else 0.8

        if inj_score >= 0.5 and llm_score >= 0.6:
            return await self._block(res_llm, trace, user_id, ip, db)

        if llm_score > threshold:
            return await self._block(res_llm, trace, user_id, ip, db)

        result = {"allowed": True, "status": "ALLOWED", "final_text": llm_input_text, "trace": trace}
        await redis_client.set(cache_key, json.dumps(result), ex=300)
        return result

    def _safe_log(self, res):
        return {
            "scanner": res.scanner_name,
            "status": res.status,
            "risk": res.metadata.get("risk_score", 0)
        }

    async def _block(self, res, trace, uid, ip, db):
        sev = int(res.metadata.get("risk_score", 0) * 10) or 3
        await handle_violation(db, uid, ip, res.message, sev)
        return {"allowed": False, "status": "BLOCKED", "block_reason": res.message, "trace": trace}

async def handle_violation(db: AsyncSession, user_id: int, ip: str, reason: str, severity: int):
    try:
        user_key = f"violation:user:{user_id}"
        ip_key = f"violation:ip:{ip}"

        u_score = await redis_client.incrby(user_key, severity)
        await redis_client.incrby(ip_key, severity)

        await redis_client.expire(user_key, 3600)
        await redis_client.expire(ip_key, 3600)

        if u_score >= 50:
            logger.warning(f"USER BANNED: {user_id}")
            await redis_client.set(f"banned:user:{user_id}", "1", ex=1800)

        logger.info(f"Violation: User={user_id} Sev={severity} Reason={reason}")
    except Exception as e:
        logger.error(f"Firewall Error: {e}")