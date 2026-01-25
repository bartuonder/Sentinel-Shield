from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.schemas.ai import AnalyzeRequest, AnalyzeResponse
from app.security.manager import SecurityPipeline
from app.security.base import ScanStatus
from app.services.logger import log_security_event
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter()

def get_security_pipeline():
    return SecurityPipeline()

@router.post("/secure", response_model=AnalyzeResponse)
async def secure_chat(
        request: Request,
        body: AnalyzeRequest,
        db: AsyncSession = Depends(get_db),
        pipeline: SecurityPipeline = Depends(get_security_pipeline),
        current_user: User = Depends(get_current_user)
):

    result = await pipeline.run(body.text)
    client_ip = request.client.host

    await log_security_event(
        db=db,
        ip=client_ip,
        endpoint="/api/v1/chat/secure",
        request_text=body.text,
        result=result,
        user_id=current_user.id
    )

    if not result["allowed"]:
        error_detail = "Security Policy Violation"
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
        "system_response": f"Merhaba {current_user.full_name}, mesajınız temiz ve onaylandı."
    }