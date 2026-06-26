from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.schemas import DetectionResult, EventStatus, Metrics, NetworkFlow, SecurityEvent


class EventStore:
    def __init__(self, path: Path, max_events: int = 5000) -> None:
        self.path = path
        self.max_events = max_events
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_json TEXT NOT NULL,
                    detection_json TEXT NOT NULL,
                    is_alert INTEGER NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_alert ON events(is_alert, severity)")

    @property
    def ready(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def add(self, flow: NetworkFlow, detection: DetectionResult) -> SecurityEvent:
        created_at = datetime.now(timezone.utc)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO events(flow_json, detection_json, is_alert, attack_type, severity, risk_score, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.model_dump_json(), detection.model_dump_json(), int(detection.is_alert),
                    detection.attack_type, detection.severity.value, detection.risk_score,
                    EventStatus.NEW.value, created_at.isoformat(),
                ),
            )
            connection.execute(
                "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)",
                (self.max_events,),
            )
            event_id = int(cursor.lastrowid)
        return SecurityEvent(id=event_id, flow=flow, detection=detection, status=EventStatus.NEW, created_at=created_at)

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            id=row["id"],
            flow=NetworkFlow.model_validate_json(row["flow_json"]),
            detection=DetectionResult.model_validate_json(row["detection_json"]),
            status=EventStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def list_events(self, limit: int = 50, alerts_only: bool = True, severity: str | None = None) -> list[SecurityEvent]:
        clauses: list[str] = []
        params: list[object] = []
        if alerts_only:
            clauses.append("is_alert = 1")
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?", params).fetchall()
        return [self._row_to_event(row) for row in rows]

    def update_status(self, event_id: int, status: EventStatus) -> SecurityEvent | None:
        with self._connect() as connection:
            cursor = connection.execute("UPDATE events SET status = ? WHERE id = ?", (status.value, event_id))
            if cursor.rowcount == 0:
                return None
            row = connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return self._row_to_event(row)

    def metrics(self) -> Metrics:
        with self._connect() as connection:
            summary = connection.execute(
                """
                SELECT COUNT(*) total,
                       COALESCE(SUM(is_alert), 0) alerts,
                       COALESCE(SUM(CASE WHEN severity = 'critical' AND is_alert = 1 THEN 1 ELSE 0 END), 0) critical,
                       COALESCE(SUM(CASE WHEN is_alert = 1 AND julianday(created_at) >= julianday('now', '-1 hour') THEN 1 ELSE 0 END), 0) last_hour,
                       COALESCE(AVG(CASE WHEN is_alert = 1 THEN risk_score END), 0) avg_risk
                FROM events
                """
            ).fetchone()
            attack_rows = connection.execute(
                "SELECT attack_type, COUNT(*) count FROM events WHERE is_alert = 1 GROUP BY attack_type ORDER BY count DESC"
            ).fetchall()
            severity_rows = connection.execute(
                "SELECT severity, COUNT(*) count FROM events WHERE is_alert = 1 GROUP BY severity"
            ).fetchall()
            timeline_rows = connection.execute(
                """
                SELECT strftime('%H:%M', created_at) bucket, COUNT(*) count
                FROM events WHERE is_alert = 1 AND julianday(created_at) >= julianday('now', '-1 hour')
                GROUP BY bucket ORDER BY bucket
                """
            ).fetchall()
        total = int(summary["total"])
        alerts = int(summary["alerts"])
        return Metrics(
            total_flows=total,
            total_alerts=alerts,
            critical_alerts=int(summary["critical"]),
            alerts_last_hour=int(summary["last_hour"]),
            detection_rate=round(alerts / total * 100, 2) if total else 0.0,
            average_risk=round(float(summary["avg_risk"]), 1),
            by_attack_type={row["attack_type"]: row["count"] for row in attack_rows},
            by_severity={row["severity"]: row["count"] for row in severity_rows},
            timeline=[{"time": row["bucket"], "count": row["count"]} for row in timeline_rows],
        )

    def clear(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM events")
