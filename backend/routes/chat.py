from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ai.explainer import chat_about_vulnerability, general_security_chat
from services.history_store import list_scans

router = APIRouter()

class ChatRequest(BaseModel):
    code: str
    vulnerability_details: str
    user_question: str
    language: str = "python"

class ChatResponse(BaseModel):
    answer: str

class AssistantChatRequest(BaseModel):
    user_question: str
    include_recent_scans: bool = True

@router.post("/chat", response_model=ChatResponse)
async def security_chat(request: ChatRequest):
    """
    Endpoint for asking follow-up questions about a vulnerability.
    """
    try:
        answer = await chat_about_vulnerability(
            code=request.code,
            vulnerability_details=request.vulnerability_details,
            user_question=request.user_question,
            language=request.language
        )
        return ChatResponse(answer=answer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assistant-chat", response_model=ChatResponse)
async def assistant_chat(request: AssistantChatRequest):
    """
    App-wide AI security chatbot endpoint.
    """
    try:
        recent_scans = list_scans() if request.include_recent_scans else []
        answer = await general_security_chat(
            user_question=request.user_question,
            recent_scans=recent_scans,
        )
        return ChatResponse(answer=answer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
