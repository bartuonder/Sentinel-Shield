from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.schemas.ai import AnalyzeRequest, AnalyzeResponse
from app.security.manager import SecurityPipeline
from app.security.base import ScanStatus
from app.services.logger import log_security_event
from app.models.user import User
from app.core.redis_client import redis_client

router = APIRouter()

def get_security_pipeline():
    return SecurityPipeline()

def get_authenticated_user(request: Request):
    if not hasattr(request.state, "user") or request.state.user is None:
        raise HTTPException(status_code=401, detail="Authentication required (API Key missing)")
    return request.state.user

@router.post("/secure", response_model=AnalyzeResponse)
async def secure_chat(
        request: Request,
        body: AnalyzeRequest,
        db: AsyncSession = Depends(get_db),
        pipeline: SecurityPipeline = Depends(get_security_pipeline),
        current_user: User = Depends(get_authenticated_user)
):

    attacker_ip = body.user_ip
    user_id = current_user.id
    user_name = current_user.full_name

    ban_key = f"banned:{user_id}:{attacker_ip}"
    is_banned = await redis_client.get(ban_key)

    if is_banned:
        raise HTTPException(
            status_code=403,
            detail="ERİŞİM ENGELLENDİ: Bu IP adresi daha önceki saldırılar nedeniyle kalıcı olarak banlanmıştır."
        )

    result = await pipeline.run(body.text, user_id=user_id, ip=attacker_ip, db=db)

    await log_security_event(
        db=db,
        ip=attacker_ip,
        endpoint="/api/v1/chat/secure",
        request_text=body.text,
        result=result,
        user_id=user_id
    )

    if not result["allowed"]:

        error_detail = result.get("block_reason", "Security Policy Violation")
        status_code = 403

        if result["status"] == ScanStatus.ERROR:
            error_detail = "Security System Unavailable"
            status_code = 503

        raise HTTPException(
            status_code=status_code,
            detail=error_detail
        )

    return {
        "status": "Message Allowed",
        "processed_input": result["final_text"],
        "system_response": f"Merhaba {user_name}, mesajınız temiz."
    }