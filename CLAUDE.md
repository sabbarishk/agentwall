# AgentWall

Open-source compliance-first AI agent runtime.
Sits between AI agents and real systems.
Enforces policies, sandboxes execution, logs tamper-proof, human approval for high-risk actions.

## Problem
OpenClaw 2026 security crisis. Regulated industries cannot deploy agents without HIPAA/NIST/SOC2 compliance. No open-source solution exists.

## Stack
Python 3.11+, FastAPI, Docker, SQLite, SHA-256, React, YAML

## Build Order
Layer 1: Core skeleton (policy engine, audit logger, sandbox, API)
Layer 2: Compliance packs (HIPAA, NIST, SOC2)
Layer 3: Framework adapters (LangChain, Anthropic, OpenAI)

## Status
Starting Layer 1 skeleton now.
