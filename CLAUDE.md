# AgentWall

Open-source compliance-first AI agent runtime.
Sits between AI agents and real systems.
Enforces policies, sandboxes execution, logs tamper-proof, human approval for high-risk actions.

---

## PERMANENT RULES — Follow for Every Single Change

**RULE 1: Commit and push after every change.**
After adding, modifying, or deleting any file, run:
```
git add .
git commit -m "<descriptive message>"
git push origin main
```

**RULE 2: Update CLAUDE.md after every change.**
Reflect the current project status, what was just built, and what comes next. Update the CURRENT STATUS section at the bottom.

**RULE 3: Update README.md after every significant change.**
Keep README.md accurate to the current state of the project — features built, setup instructions, architecture.

**RULE 4: Every commit message must be descriptive.**
Bad: `update`, `fix`, `changes`
Good: `add SHA-256 hash chaining to audit logger`, `implement Docker sandbox execute method`, `add HIPAA compliance pack with PHI detection rules`

---

## Problem
OpenClaw 2026 security crisis. Regulated industries cannot deploy agents without HIPAA/NIST/SOC2 compliance. No open-source solution exists.

## Stack
Python 3.11+, FastAPI, Docker, SQLite, SHA-256, React, YAML

## Build Order
Layer 1: Core skeleton (policy engine, audit logger, sandbox, API)
Layer 2: Compliance packs (HIPAA, NIST, SOC2)
Layer 3: Framework adapters (LangChain, Anthropic, OpenAI)

---

## CURRENT STATUS
_Updated: 2026-06-07_

### Built
- `requirements.txt` — fastapi, uvicorn, pyyaml, docker, aiosqlite, pydantic
- `agentwall/__init__.py` — package init
- `agentwall/policy.py` — PolicyEngine: loads YAML, evaluates tool_name → allow/deny/require_approval
- `agentwall/audit.py` — AuditLogger: async SQLite writer with SHA-256 hash chaining per entry
- `agentwall/sandbox.py` — DockerSandbox: runs Python callables in isolated Docker containers (no network, memory/CPU limits)
- `agentwall/runtime.py` — AgentWall: composes policy + audit + sandbox; wrap(tool_fn) returns a policy-enforced async function
- `agentwall/api.py` — FastAPI app: POST /execute, GET /audit/logs, GET /health
- `policies/default.yaml` — sample policy: allow read_file/call_api, require_approval send_email, deny execute_shell
- `examples/basic_agent.py` — working example wrapping two tools, demonstrating allow and deny paths

### Working
- Layer 1 skeleton complete
- Policy evaluation from YAML rules
- Tamper-proof audit log with SHA-256 hash chaining to SQLite
- Docker sandbox with network isolation and resource limits
- AgentWall runtime wrapping any callable
- FastAPI gateway with execute, audit, and health endpoints

### Next
- Layer 2: Compliance packs
  - HIPAA pack: PHI detection rules, minimum necessary access
  - NIST pack: access control categories, incident logging
  - SOC2 pack: availability and confidentiality rules
