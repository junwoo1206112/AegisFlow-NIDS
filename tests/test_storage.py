from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.detector import HybridDetector
from app.schemas import EventStatus, NetworkFlow
from app.storage import EventStore


def make_flow() -> NetworkFlow:
    return NetworkFlow(
        src_ip="203.0.113.10", dst_ip="10.20.1.11", src_port=50000, dst_port=22,
        protocol="TCP", duration_ms=20_000, packets=240, bytes_total=90_000,
        tcp_syn_count=20, failed_logins=15, connections_last_minute=120,
        unique_ports_last_minute=2,
    )


def test_event_lifecycle_and_metrics(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    flow = make_flow()
    event = store.add(flow, HybridDetector(seed=42).predict(flow))
    assert event.id > 0
    assert store.list_events()[0].detection.event_type == "Repeated Access Failure"
    updated = store.update_status(event.id, EventStatus.INVESTIGATING)
    assert updated and updated.status is EventStatus.INVESTIGATING
    metrics = store.metrics()
    assert metrics.total_flows == 1
    assert metrics.total_alerts == 1
    assert metrics.by_event_type == {"Repeated Access Failure": 1}


def test_store_retention_limit(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "retention.db", max_events=2)
    detector = HybridDetector(seed=42)
    for _ in range(3):
        flow = make_flow()
        store.add(flow, detector.predict(flow))
    assert len(store.list_events(limit=10, alerts_only=False)) == 2


def test_store_migrates_legacy_attack_type_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    flow = make_flow()
    detection = HybridDetector(seed=42).predict(flow).model_dump(mode="json")
    detection["attack_type"] = detection.pop("event_type")
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE events (
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
        connection.execute(
            """
            INSERT INTO events(flow_json, detection_json, is_alert, attack_type, severity, risk_score, status, created_at)
            VALUES (?, ?, 1, ?, ?, ?, 'new', '2026-06-27T00:00:00+00:00')
            """,
            (
                flow.model_dump_json(),
                json.dumps(detection),
                detection["attack_type"],
                detection["severity"],
                detection["risk_score"],
            ),
        )

    store = EventStore(db_path)
    event = store.list_events()[0]
    assert event.detection.event_type == "Repeated Access Failure"
    assert store.metrics().by_event_type == {"Repeated Access Failure": 1}
