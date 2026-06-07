import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentwall.runtime import AgentWall


def read_file(path: str) -> str:
    return f"[simulated] contents of {path}"


def execute_shell(cmd: str) -> str:
    return f"[simulated] ran: {cmd}"


async def main():
    wall = AgentWall(policy_path="policies/default.yaml")

    safe_read = wall.wrap(read_file)
    blocked_shell = wall.wrap(execute_shell)

    print("--- Calling read_file (should be allowed) ---")
    result = await safe_read("secrets.txt")
    print(f"Result: {result}")

    print("\n--- Calling execute_shell (should be denied) ---")
    try:
        await blocked_shell("rm -rf /")
    except PermissionError as e:
        print(f"Blocked: {e}")


if __name__ == "__main__":
    asyncio.run(main())
