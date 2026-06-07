import asyncio
import uuid
from typing import Callable

from .audit import AuditLogger
from .policy import PolicyEngine
from .sandbox import DockerSandbox


class AgentWall:
    def __init__(self, policy_path: str, db_path: str = "agentwall_audit.db", use_sandbox: bool = False):
        self._policy = PolicyEngine(policy_path)
        self._audit = AuditLogger(db_path)
        self._sandbox = DockerSandbox() if use_sandbox else None

    def wrap(self, tool_fn: Callable) -> Callable:
        tool_name = tool_fn.__name__
        wall = self

        async def protected(*args, **kwargs):
            action_id = str(uuid.uuid4())
            outcome = self._policy.evaluate(tool_name)

            await wall._audit.log_event(action_id, tool_name, "policy_check", outcome)

            if outcome == "deny":
                await wall._audit.log_event(action_id, tool_name, "execution", "denied")
                raise PermissionError(f"Tool '{tool_name}' is denied by policy.")

            if outcome == "require_approval":
                await wall._audit.log_event(action_id, tool_name, "execution", "pending_approval")
                raise PermissionError(f"Tool '{tool_name}' requires human approval.")

            try:
                if wall._sandbox:
                    result = await wall._sandbox.execute(tool_fn, *args, **kwargs)
                elif asyncio.iscoroutinefunction(tool_fn):
                    result = await tool_fn(*args, **kwargs)
                else:
                    result = tool_fn(*args, **kwargs)

                await wall._audit.log_event(action_id, tool_name, "execution", "success", str(result))
                return result

            except Exception as exc:
                await wall._audit.log_event(action_id, tool_name, "execution", "error", str(exc))
                raise

        protected.__name__ = f"protected_{tool_name}"
        return protected
