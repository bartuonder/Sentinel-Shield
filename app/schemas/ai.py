from pydantic import BaseModel

class AnalyzeRequest(BaseModel):
    text: str
    user_ip: str

class AnalyzeResponse(BaseModel):
    status: str
    processed_input: str
    system_response: str