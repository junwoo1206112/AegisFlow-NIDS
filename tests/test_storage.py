from __future__ import annotations

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
    assert store.list_events()[0].detection.attack_type == "Brute Force"
    updated = store.update_status(event.id, EventStatus.INVESTIGATING)
    assert updated and updated.status is EventStatus.INVESTIGATING
    metrics = store.metrics()
    assert metrics.total_flows == 1
    assert metrics.total_alerts == 1
    assert metrics.by_attack_type == {"Brute Force": 1}


def test_store_retention_limit(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "retention.db", max_events=2)
    detector = HybridDetector(seed=42)
    for _ in range(3):
        flow = make_flow()
        store.add(flow, detector.predict(flow))
    assert len(store.list_events(limit=10, alerts_only=False)) == 2

