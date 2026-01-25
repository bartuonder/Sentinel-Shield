from sqlalchemy.ext.asyncio import AsyncSession
from app.models.security import SecurityLog
from app.security.base import ScanStatus


async def log_security_event(
        db: AsyncSession,
        ip: str,
        endpoint: str,
        request_text: str,
        result: dict,
        user_id: int = None
):

    trace = result.get("trace", [])
    last_trace = trace[-1] if trace else {}

    scanner_name = "System"
    if trace:

        for step in trace:
            if step["status"] != ScanStatus.ALLOWED:
                scanner_name = step["scanner"]
                break
        else:
            scanner_name = trace[-1]["scanner"]

    new_log = SecurityLog(
        client_ip=ip,
        endpoint=endpoint,
        user_id=user_id,
        request_text=request_text,
        sanitized_text=result.get("final_text", ""),
        status=result.get("status", ScanStatus.ERROR),
        scanner_name=scanner_name,
        metadata_log={"trace": trace, "block_reason": result.get("block_reason")},
        risk_score=0.0
    )

    db.add(new_log)
    await db.commit()
