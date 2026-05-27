"""
FastAPI integration — Paladin wraps every LLM route.
Run: uvicorn examples.fastapi_app:app --reload
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from paladin import Paladin

app = FastAPI(title="Paladin-Protected API")
p = Paladin(mode="default", injection_threshold=0.6, audit_path="./logs/audit.log")


class ChatRequest(BaseModel):
    user_id: str
    message: str


class ChatResponse(BaseModel):
    response: str


def call_llm(prompt: str) -> str:
    # Replace with real LLM call
    return f"[LLM response to: {prompt[:50]}...]"


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    from bulwark.scanner import InjectionRiskError
    from vault.scanner import SecretsLeakError

    try:
        with p.guard(req.user_id, "chat") as ctx:
            ctx.check_input(req.message)
            raw_response = call_llm(ctx.clean_input)
            ctx.record_output(raw_response)
        return ChatResponse(response=ctx.rehydrate(raw_response))
    except InjectionRiskError as e:
        raise HTTPException(status_code=400, detail=f"Input blocked: {e.reasons}")
    except SecretsLeakError:
        raise HTTPException(status_code=400, detail="Input contains credentials")
