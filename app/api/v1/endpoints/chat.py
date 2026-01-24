from fastapi import APIRouter, HTTPException
from app.schemas.ai import AnalyzeRequest, AnalyzeResponse
from app.security.manager import SecurityPipeline

router = APIRouter()
pipeline = SecurityPipeline()


@router.post("/secure", response_model=AnalyzeResponse)
async def secure_chat(request: AnalyzeRequest):

    result = await pipeline.run(request.text)

    if not result["final_allowed"]:
        raise HTTPException(
            status_code=403,
            detail=result["block_reason"]
        )

    return {
        "status": "Message Allowed",
        "processed_input": result["final_text"],
        "system_response": "Ben güvenli bir AI asistanıyım."
    }