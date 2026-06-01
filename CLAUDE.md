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
_Updated: 2026-05-31_

### Built
- CLAUDE.md with project definition and permanent rules

### Working
- Nothing yet — Layer 1 skeleton not started

### Next
- Layer 1: Core skeleton
  - Policy engine (YAML-based rule evaluation)
  - Audit logger (SHA-256 hash chaining, tamper-proof)
  - Docker sandbox (isolated execution environment)
  - FastAPI gateway (agent request interception)
