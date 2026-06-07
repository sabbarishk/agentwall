import csv
import hashlib
import io
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Literal

import aiosqlite

DB_PATH = "agentwall_audit.db"

_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS audit_log (
        id              TEXT PRIMARY KEY,
        action_id       TEXT NOT NULL,
        session_id      TEXT,
        agent_id        TEXT,
        user_id         TEXT,
        tool_name       TEXT NOT NULL,
        event_type      TEXT NOT NULL,
        outcome         TEXT NOT NULL,
        risk_level      TEXT,
        detail          TEXT,
        input_summary   TEXT,
        output_summary  TEXT,
        ip_address      TEXT,
        timestamp       TEXT NOT NULL,
        previous_hash   TEXT NOT NULL,
        current_hash    TEXT NOT NULL
    )
"""

_ALL_FIELDS = (
    "id", "action_id", "session_id", "agent_id", "user_id",
    "tool_name", "event_type", "outcome", "risk_level", "detail",
    "input_summary", "output_summary", "ip_address", "timestamp",
    "previous_hash", "current_hash",
)


def _compute_hash(previous_hash: str, action_id: str, tool_name: str,
                  event_type: str, outcome: str, timestamp: str) -> str:
    payload = previous_hash + action_id + tool_name + event_type + outcome + timestamp
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLogger:
    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._last_hash = "0" * 64

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _init_db(self, db: aiosqlite.Connection):
        await db.execute(_CREATE_TABLE)
        await db.commit()
        row = await (
            await db.execute(
                "SELECT current_hash FROM audit_log ORDER BY rowid DESC LIMIT 1"
            )
        ).fetchone()
        if row:
            self._last_hash = row[0]

    async def _rows_ordered(self, db: aiosqlite.Connection) -> list[dict]:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            f"SELECT {', '.join(_ALL_FIELDS)} FROM audit_log ORDER BY rowid ASC"
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def log_event(
        self,
        action_id: str,
        tool_name: str,
        event_type: str,
        outcome: str,
        *,
        session_id: str = "",
        agent_id: str = "",
        user_id: str = "",
        risk_level: str = "low",
        detail: str = "",
        input_summary: str = "",
        output_summary: str = "",
        ip_address: str = "",
    ) -> str:
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        previous_hash = self._last_hash
        current_hash = _compute_hash(
            previous_hash, action_id, tool_name, event_type, outcome, timestamp
        )

        async with aiosqlite.connect(self._db_path) as db:
            await self._init_db(db)
            await db.execute(
                f"INSERT INTO audit_log ({', '.join(_ALL_FIELDS)}) VALUES ({', '.join(['?']*len(_ALL_FIELDS))})",
                (
                    entry_id, action_id, session_id, agent_id, user_id,
                    tool_name, event_type, outcome, risk_level, detail,
                    input_summary, output_summary, ip_address, timestamp,
                    previous_hash, current_hash,
                ),
            )
            await db.commit()

        self._last_hash = current_hash
        return current_hash

    async def get_all_logs(self) -> list[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            await self._init_db(db)
            return await self._rows_ordered(db)

    async def verify_chain(self) -> dict:
        verification_timestamp = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            await self._init_db(db)
            rows = await self._rows_ordered(db)

        tampered: list[str] = []
        running_hash = "0" * 64

        for row in rows:
            expected = _compute_hash(
                running_hash,
                row["action_id"],
                row["tool_name"],
                row["event_type"],
                row["outcome"],
                row["timestamp"],
            )
            if expected != row["current_hash"] or running_hash != row["previous_hash"]:
                tampered.append(row["id"])
            running_hash = row["current_hash"]

        return {
            "is_valid": len(tampered) == 0,
            "total_entries": len(rows),
            "tampered_entries": tampered,
            "verification_timestamp": verification_timestamp,
        }

    async def check_anomalies(self) -> list[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            await self._init_db(db)
            rows = await self._rows_ordered(db)

        anomalies: list[dict] = []
        now = datetime.now(timezone.utc)

        # Bucket denied actions by agent_id within a sliding 10-minute window
        denied_by_agent: dict[str, list[datetime]] = defaultdict(list)
        # Bucket tool calls by tool_name within a sliding 1-minute window
        calls_by_tool: dict[str, list[datetime]] = defaultdict(list)

        for row in rows:
            ts = datetime.fromisoformat(row["timestamp"])

            if row["risk_level"] == "critical":
                anomalies.append({
                    "type": "critical_risk_action",
                    "severity": "critical",
                    "detail": f"action_id={row['action_id']} tool={row['tool_name']} agent={row['agent_id']}",
                    "timestamp": row["timestamp"],
                })

            if row["outcome"] == "denied" and row["agent_id"]:
                window_start = ts - timedelta(minutes=10)
                denied_by_agent[row["agent_id"]].append(ts)
                recent = [t for t in denied_by_agent[row["agent_id"]] if t >= window_start]
                denied_by_agent[row["agent_id"]] = recent
                if len(recent) > 5:
                    anomalies.append({
                        "type": "excessive_denials",
                        "severity": "high",
                        "detail": (
                            f"agent_id={row['agent_id']} had {len(recent)} denied actions "
                            f"within 10 minutes"
                        ),
                        "timestamp": row["timestamp"],
                    })

            if row["tool_name"]:
                window_start = ts - timedelta(minutes=1)
                calls_by_tool[row["tool_name"]].append(ts)
                recent = [t for t in calls_by_tool[row["tool_name"]] if t >= window_start]
                calls_by_tool[row["tool_name"]] = recent
                if len(recent) > 20:
                    anomalies.append({
                        "type": "tool_call_flood",
                        "severity": "high",
                        "detail": (
                            f"tool={row['tool_name']} called {len(recent)} times "
                            f"within 1 minute"
                        ),
                        "timestamp": row["timestamp"],
                    })

        return anomalies

    async def export_logs(self, format: Literal["json", "csv"] = "json") -> str:
        rows = await self.get_all_logs()

        if format == "json":
            return json.dumps(rows, indent=2)

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(_ALL_FIELDS))
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue()

    async def get_session_summary(self, session_id: str) -> dict:
        async with aiosqlite.connect(self._db_path) as db:
            await self._init_db(db)
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                f"SELECT {', '.join(_ALL_FIELDS)} FROM audit_log "
                "WHERE session_id = ? ORDER BY rowid ASC",
                (session_id,),
            )
            rows = [dict(r) for r in await cursor.fetchall()]

        by_action: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            by_action[row["action_id"]].append(row)

        actions = []
        for action_id, events in by_action.items():
            actions.append({
                "action_id": action_id,
                "tool_name": events[0]["tool_name"],
                "agent_id": events[0]["agent_id"],
                "user_id": events[0]["user_id"],
                "final_outcome": events[-1]["outcome"],
                "risk_level": events[-1]["risk_level"],
                "started_at": events[0]["timestamp"],
                "ended_at": events[-1]["timestamp"],
                "events": events,
            })

        return {
            "session_id": session_id,
            "total_actions": len(actions),
            "total_events": len(rows),
            "actions": actions,
        }
