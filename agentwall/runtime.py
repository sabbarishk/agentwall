import asyncio
import uuid
from typing import Callable

from .audit import AuditLogger
from .policy import PolicyEngine
from .sandbox import DockerSandbox

_RISK_MAP = {
    "allow": "low",
    "require_approval": "medium",
    "deny": "high",
}


class AgentWall:
    def __init__(
        self,
        policy_path: str,
        db_path: str = "agentwall_audit.db",
        use_sandbox: bool = False,
        session_id: str = "",
        agent_id: str = "",
        user_id: str = "",
    ):
        self._policy = PolicyEngine(policy_path)
        self._audit = AuditLogger(db_path)
        self._sandbox = DockerSandbox() if use_sandbox else None
        self._session_id = session_id or str(uuid.uuid4())
        self._agent_id = agent_id
        self._user_id = user_id

    def wrap(self, tool_fn: Callable) -> Callable:
        tool_name = tool_fn.__name__
        wall = self

        async def protected(*args, **kwargs):
            action_id = str(uuid.uuid4())
            policy_outcome = wall._policy.evaluate(tool_name)
            risk_level = _RISK_MAP.get(policy_outcome, "low")

            shared = dict(
                session_id=wall._session_id,
                agent_id=wall._agent_id,
                user_id=wall._user_id,
                risk_level=risk_level,
            )

            await wall._audit.log_event(
                action_id, tool_name, "policy_check", policy_outcome, **shared
            )

            if policy_outcome == "deny":
                await wall._audit.log_event(
                    action_id, tool_name, "execution", "denied", **shared
                )
                raise PermissionError(f"Tool '{tool_name}' is denied by policy.")

            if policy_outcome == "require_approval":
                await wall._audit.log_event(
                    action_id, tool_name, "execution", "pending_approval", **shared
                )
                raise PermissionError(f"Tool '{tool_name}' requires human approval.")

            input_summary = f"args={args!r} kwargs={kwargs!r}"

            try:
                if wall._sandbox:
                    result = await wall._sandbox.execute(tool_fn, *args, **kwargs)
                elif asyncio.iscoroutinefunction(tool_fn):
                    result = await tool_fn(*args, **kwargs)
                else:
                    result = tool_fn(*args, **kwargs)

                await wall._audit.log_event(
                    action_id, tool_name, "execution", "success",
                    input_summary=input_summary,
                    output_summary=str(result)[:500],
                    **shared,
                )
                return result

            except Exception as exc:
                await wall._audit.log_event(
                    action_id, tool_name, "execution", "error",
                    detail=str(exc),
                    input_summary=input_summary,
                    **shared,
                )
                raise

        protected.__name__ = f"protected_{tool_name}"
        return protected
