import uuid
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .audit import AuditLogger
from .policy import PolicyEngine

app = FastAPI(title="AgentWall", description="Compliance-first AI agent runtime")

_policy = PolicyEngine("policies/default.yaml")
_audit = AuditLogger()


class ExecuteRequest(BaseModel):
    tool_name: str
    session_id: str = ""
    agent_id: str = ""
    user_id: str = ""
    ip_address: str = ""
    detail: str = ""
    input_summary: str = ""


@app.post("/execute")
async def execute_tool(request: ExecuteRequest):
    action_id = str(uuid.uuid4())
    outcome = _policy.evaluate(request.tool_name)
    risk_level = "high" if outcome == "deny" else "medium" if outcome == "require_approval" else "low"

    shared = dict(
        session_id=request.session_id,
        agent_id=request.agent_id,
        user_id=request.user_id,
        ip_address=request.ip_address,
        risk_level=risk_level,
        input_summary=request.input_summary,
    )

    await _audit.log_event(
        action_id, request.tool_name, "policy_check", outcome,
        detail=request.detail, **shared
    )

    if outcome == "deny":
        await _audit.log_event(action_id, request.tool_name, "execution", "denied", **shared)
        raise HTTPException(status_code=403, detail=f"Tool '{request.tool_name}' is denied by policy.")

    if outcome == "require_approval":
        await _audit.log_event(action_id, request.tool_name, "execution", "pending_approval", **shared)
        raise HTTPException(status_code=202, detail=f"Tool '{request.tool_name}' requires human approval.")

    await _audit.log_event(action_id, request.tool_name, "execution", "success", **shared)
    return {"action_id": action_id, "tool_name": request.tool_name, "outcome": outcome}


@app.get("/audit/logs")
async def get_audit_logs():
    logs = await _audit.get_all_logs()
    return {"count": len(logs), "logs": logs}


@app.get("/audit/verify")
async def verify_chain():
    return await _audit.verify_chain()


@app.get("/audit/anomalies")
async def check_anomalies():
    anomalies = await _audit.check_anomalies()
    return {"count": len(anomalies), "anomalies": anomalies}


@app.get("/audit/export")
async def export_logs(format: Literal["json", "csv"] = Query(default="json")):
    content = await _audit.export_logs(format=format)
    media = "text/csv" if format == "csv" else "application/json"
    return PlainTextResponse(content=content, media_type=media)


@app.get("/audit/session/{session_id}")
async def get_session_summary(session_id: str):
    return await _audit.get_session_summary(session_id)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "AgentWall"}
