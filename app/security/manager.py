import json
import logging
import asyncio
import base64
import re
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
LLM_TIMEOUT = 4.0
BAN_THRESHOLD = 5


class SecurityPipeline:
    def __init__(self):
        self.validator = InputValidator()
        self.pii = PIIScanner()
        self.injection = InjectionScanner()
        self.llm = LLMGuardScanner()
        self.PIPELINE_VERSION = "v6_STABLE"
        self.MODE = "strict"
        self.BLOCK_ON_CRITICAL_PII = True

    async def check_rate_limits(self, user_id: int, ip: str) -> bool:
        if not redis_client: return True
        try:
            user_key = f"ratelimit:user:{user_id}"
            ip_key = f"ratelimit:ip:{ip}"
            pipe = redis_client.pipeline()
            pipe.incr(user_key)
            pipe.expire(user_key, 60)
            pipe.incr(ip_key)
            pipe.expire(ip_key, 60)
            results = await pipe.execute()
            if results[0] > 1000: return False
            if results[2] > 100: return False
        except Exception:
            return True
        return True

    async def get_combined_context(self, user_id: int, current_text: str) -> str:
        if not redis_client: return current_text
        try:
            context_key = f"context:last_msg:{user_id}"
            last_msg = await redis_client.get(context_key)
            await redis_client.set(context_key, current_text[-MAX_CONTEXT_LEN:], ex=300)
            if last_msg:
                return f"{last_msg[-MAX_CONTEXT_LEN:]}\n{current_text}"
        except Exception:
            pass
        return current_text

    def _decode_aggressive(self, text: str) -> str:
        if not text: return ""
        processed_text = text
        try:
            potential_matches = set(re.findall(r'[A-Za-z0-9+/=]{8,}', text))
            for encoded in potential_matches:
                try:
                    missing_padding = len(encoded) % 4
                    if missing_padding:
                        encoded += '=' * (4 - missing_padding)
                    decoded_bytes = base64.b64decode(encoded, validate=True)
                    decoded_str = decoded_bytes.decode('utf-8')
                    if decoded_str.isprintable() and len(decoded_str) > 3:
                        processed_text = processed_text.replace(encoded, decoded_str)
                except Exception:
                    continue
        except Exception:
            pass
        return processed_text

    def _safe_status_str(self, status):
        if hasattr(status, 'value'):
            return status.value
        return str(status)

    def _safe_log_dict(self, res):
        return {
            "scanner": res.scanner_name,
            "status": self._safe_status_str(res.status),
            "risk": (res.metadata or {}).get("risk_score", 0)
        }

    async def run(self, text: str, user_id: int, ip: str, db: AsyncSession):
        trace = []
        try:
            if redis_client:
                is_ip_banned = await redis_client.get(f"banned:ip:{ip}")
                if is_ip_banned:
                    return {
                        "allowed": False,
                        "status": "BANNED",
                        "block_reason": "IP Permanently Banned",
                        "final_text": text,
                        "trace": []
                    }

                if "." in ip and ":" not in ip:
                    subnet = ".".join(ip.split(".")[:3])
                    if await redis_client.get(f"banned:subnet:{subnet}"):
                        return {
                            "allowed": False,
                            "status": "BANNED",
                            "block_reason": "Subnet Banned",
                            "final_text": text,
                            "trace": []
                        }

            if not await self.check_rate_limits(user_id, ip):
                return {
                    "allowed": False,
                    "status": "BLOCKED",
                    "reason": "Rate Limit",
                    "block_reason": "Rate Limit Exceeded",
                    "final_text": text,
                    "trace": []
                }

            decoded_text = self._decode_aggressive(text)

            res_val = await self.validator.scan(decoded_text)
            trace.append(self._safe_log_dict(res_val))
            if res_val.status == ScanStatus.BLOCKED:
                return await self._finalize(res_val, trace, user_id, ip, db)

            clean_text = res_val.sanitized_text
            combined_text = await self.get_combined_context(user_id, clean_text)

            res_inj = await self.injection.scan(combined_text)
            trace.append(self._safe_log_dict(res_inj))

            inj_risk = (res_inj.metadata or {}).get("risk_score", 0)
            if inj_risk >= 1.0:
                return await self._finalize(res_inj, trace, user_id, ip, db)

            res_pii = await self.pii.scan(clean_text)
            trace.append(self._safe_log_dict(res_pii))

            pii_meta = res_pii.metadata or {}
            detected = pii_meta.get("detected_types", [])

            if pii_meta.get("hidden_pii"):
                return await self._finalize(res_pii, trace, user_id, ip, db)

            criticals = ["TR_TCKN_HIDDEN", "HIDDEN_PII"]
            if self.BLOCK_ON_CRITICAL_PII and any(d in criticals for d in detected):
                res_pii.status = ScanStatus.BLOCKED
                res_pii.message = "Sensitive Data Policy (Hidden)"
                return await self._finalize(res_pii, trace, user_id, ip, db)

            final_input_text = res_pii.sanitized_text

            try:
                res_llm = await asyncio.wait_for(self.llm.scan(final_input_text), timeout=LLM_TIMEOUT)
                trace.append(self._safe_log_dict(res_llm))

                if res_llm.status == ScanStatus.ERROR:
                    return {
                        "allowed": False, "status": "BLOCKED", "block_reason": "Security Check Failed (LLM Error)",
                        "final_text": final_input_text, "trace": trace
                    }

                llm_score = (res_llm.metadata or {}).get("risk_score", 0)
                threshold = 0.5 if self.MODE == "strict" else 0.8

                if inj_risk >= 0.5 and llm_score >= 0.6:
                    res_llm.status = ScanStatus.BLOCKED
                    res_llm.message = "Combined Risk"
                    return await self._finalize(res_llm, trace, user_id, ip, db)

                if llm_score > threshold:
                    return await self._finalize(res_llm, trace, user_id, ip, db)

            except asyncio.TimeoutError:
                return {
                    "allowed": False, "status": "BLOCKED", "block_reason": "Security Check Timeout",
                    "final_text": final_input_text, "trace": trace
                }
            except Exception as e:
                logger.error(f"LLM Scanner Error: {e}")
                return {
                    "allowed": False, "status": "BLOCKED", "block_reason": "Security Module Error",
                    "final_text": final_input_text, "trace": trace
                }

            success_result = SecurityResult(
                status=ScanStatus.ALLOWED,
                scanner_name="System",
                message="Clean",
                sanitized_text=final_input_text
            )
            return await self._finalize(success_result, trace, user_id, ip, db)

        except Exception as e:
            logger.error(f"Manager Run Error: {e}")
            traceback.print_exc()
            return {
                "allowed": False,
                "status": "BLOCKED",
                "block_reason": f"System Error: {str(e)}",
                "final_text": text,
                "trace": trace
            }

    async def _finalize(self, res, trace, uid, ip, db):
        is_allowed = res.status != ScanStatus.BLOCKED

        if db:
            try:
                meta_dict = {
                    "trace": trace,
                    "original_msg": res.message,
                    "risk_score": (res.metadata or {}).get("risk_score", 0.0)
                }

                log = SecurityLog(
                    user_id=uid,
                    client_ip=ip,
                    endpoint="chat/secure",
                    request_text=res.sanitized_text,
                    sanitized_text=res.sanitized_text,
                    scanner_name=res.scanner_name if not is_allowed else "System",
                    status=res.status,
                    risk_score=(res.metadata or {}).get("risk_score", 0.0),
                    metadata_log=meta_dict
                )
                db.add(log)
                await db.commit()
            except Exception as e:
                logger.error(f"DB Log Error: {e}")
                traceback.print_exc()

        if not is_allowed:
            STRIKE_POINT = 1
            await handle_violation(db, uid, ip, res.message, STRIKE_POINT)
            return {
                "allowed": False,
                "status": "BLOCKED",
                "block_reason": res.message,
                "trace": trace,
                "final_text": res.sanitized_text
            }

        return {
            "allowed": True,
            "status": "ALLOWED",
            "final_text": res.sanitized_text,
            "trace": trace
        }


async def handle_violation(db: AsyncSession, user_id: int, ip: str, reason: str, severity: int):
    if not redis_client: return
    try:
        ip_key = f"violation:ip:{ip}"
        ip_score = await redis_client.incrby(ip_key, severity)
        await redis_client.expire(ip_key, 3600)

        if ip_score >= BAN_THRESHOLD:
            logger.warning(f"IP BANNED: {ip}")
            await redis_client.set(f"banned:ip:{ip}", "permanent")

            try:
                existing = await db.execute(select(BlacklistedIP).where(BlacklistedIP.ip_address == ip))
                if not existing.scalars().first():
                    new_ban = BlacklistedIP(
                        user_id=user_id,
                        ip_address=ip,
                        reason=f"Auto-Ban: 5 Strikes"
                    )
                    db.add(new_ban)
                    await db.commit()
            except Exception as e:
                logger.error(f"DB Ban Insert Error: {e}")

        logger.info(f"Violation: IP={ip} Sev={severity} Reason={reason} Score={ip_score}")
    except Exception as e:
        logger.error(f"Firewall Handle Violation Error: {e}")