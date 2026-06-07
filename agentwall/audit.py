import hashlib
import json
import uuid
from datetime import datetime, timezone

import aiosqlite

DB_PATH = "agentwall_audit.db"


class AuditLogger:
    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._last_hash = "0" * 64

    async def _ensure_table(self, db: aiosqlite.Connection):
        await db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                action_id TEXT,
                tool_name TEXT,
                event_type TEXT,
                outcome TEXT,
                timestamp TEXT,
                detail TEXT,
                hash TEXT
            )
        """)
        await db.commit()
        row = await (await db.execute("SELECT hash FROM audit_log ORDER BY rowid DESC LIMIT 1")).fetchone()
        if row:
            self._last_hash = row[0]

    async def log_event(
        self,
        action_id: str,
        tool_name: str,
        event_type: str,
        outcome: str,
        detail: str = "",
    ) -> str:
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = f"{self._last_hash}{action_id}{tool_name}{event_type}{outcome}{timestamp}{detail}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()

        async with aiosqlite.connect(self._db_path) as db:
            await self._ensure_table(db)
            await db.execute(
                "INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?)",
                (entry_id, action_id, tool_name, event_type, outcome, timestamp, detail, entry_hash),
            )
            await db.commit()

        self._last_hash = entry_hash
        return entry_hash

    async def get_all_logs(self) -> list[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            await self._ensure_table(db)
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM audit_log ORDER BY rowid ASC")
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]
