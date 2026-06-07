import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .audit import AuditLogger
from .policy import PolicyEngine

app = FastAPI(title="AgentWall", description="Compliance-first AI agent runtime")

_policy = PolicyEngine("policies/default.yaml")
_audit = AuditLogger()


class ExecuteRequest(BaseModel):
    tool_name: str
    detail: str = ""


@app.post("/execute")
async def execute_tool(request: ExecuteRequest):
    action_id = str(uuid.uuid4())
    outcome = _policy.evaluate(request.tool_name)
    await _audit.log_event(action_id, request.tool_name, "policy_check", outcome, request.detail)

    if outcome == "deny":
        await _audit.log_event(action_id, request.tool_name, "execution", "denied")
        raise HTTPException(status_code=403, detail=f"Tool '{request.tool_name}' is denied by policy.")

    if outcome == "require_approval":
        await _audit.log_event(action_id, request.tool_name, "execution", "pending_approval")
        raise HTTPException(status_code=202, detail=f"Tool '{request.tool_name}' requires human approval.")

    await _audit.log_event(action_id, request.tool_name, "execution", "success")
    return {"action_id": action_id, "tool_name": request.tool_name, "outcome": outcome}


@app.get("/audit/logs")
async def get_audit_logs():
    logs = await _audit.get_all_logs()
    return {"count": len(logs), "logs": logs}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "AgentWall"}
