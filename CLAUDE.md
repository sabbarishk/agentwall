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
- `agentwall/policy.py` — PolicyEngine: loads YAML, `evaluate(tool_name)` → allow/deny/require_approval
- `agentwall/audit.py` — **Production-grade** AuditLogger:
  - 16-field schema: id, action_id, session_id, agent_id, user_id, tool_name, event_type, outcome, risk_level, detail, input_summary, output_summary, ip_address, timestamp, previous_hash, current_hash
  - SHA-256 hash chaining: current_hash = SHA256(previous_hash + action_id + tool_name + event_type + outcome + timestamp)
  - `verify_chain()` — reads all entries, recalculates every hash, returns is_valid + tampered_entries list
  - `check_anomalies()` — detects excessive denials (>5 in 10 min per agent), critical risk actions, tool flood (>20 calls in 1 min)
  - `export_logs(format)` — exports all logs as JSON or CSV
  - `get_session_summary(session_id)` — returns all events grouped by action_id for a full session story
- `agentwall/sandbox.py` — DockerSandbox: runs Python callables in isolated Docker containers (no network, 128MB RAM, 0.5 CPU)
- `agentwall/runtime.py` — AgentWall: composes policy + audit + sandbox; `wrap(tool_fn)` returns a policy-enforced async function; passes session_id, agent_id, user_id, risk_level, input/output summaries to audit
- `agentwall/api.py` — FastAPI app:
  - `POST /execute` — run a tool through policy + audit
  - `GET /audit/logs` — all audit entries
  - `GET /audit/verify` — verify tamper-proof hash chain
  - `GET /audit/anomalies` — detect security anomalies
  - `GET /audit/export?format=json|csv` — export audit log
  - `GET /audit/session/{session_id}` — full session story grouped by action
  - `GET /health` — health check
- `policies/default.yaml` — allow: read_file, call_api — require_approval: send_email — deny: execute_shell
- `examples/basic_agent.py` — working example wrapping two tools (allow + deny paths)

### Working
- Layer 1 skeleton complete
- Policy evaluation from YAML rules
- Production-grade tamper-proof audit log with SHA-256 hash chaining, chain verification, anomaly detection, export
- Docker sandbox with network isolation and resource limits
- AgentWall runtime wrapping any callable with full audit context
- FastAPI gateway with 7 endpoints covering execute, audit, verify, anomaly, export, session, health

### Next
- Layer 2: Compliance packs
  - HIPAA pack: PHI detection rules, minimum necessary access
  - NIST pack: access control categories, incident logging
  - SOC2 pack: availability and confidentiality rules
