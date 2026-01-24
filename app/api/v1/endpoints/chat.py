from fastapi import APIRouter, HTTPException
from app.schemas.ai import AnalyzeRequest, AnalyzeResponse
from app.services.ai_guard import guard_check

router = APIRouter()


@router.post("/secure",
             response_model=AnalyzeResponse)
async def secure_chat(request: AnalyzeRequest):

    security_report = await guard_check(request.text)

    if not security_report["allowed"]:
        raise HTTPException(
            status_code=403,
            detail=f"BLOCKED BY SENTINEL: {security_report['reason']}"
        )

    return {
        "status": "Message Allowed",
        "processed_input": security_report["sanitized_input"],
        "system_response": "Ben güvenli bir AI asistanıyım. Mesajınız temiz görünüyor."
    }