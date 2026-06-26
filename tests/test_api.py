from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.storage import EventStore


PAYLOAD = {
    "src_ip": "185.220.101.45", "dst_ip": "10.20.1.10", "src_port": 50111,
    "dst_port": 443, "protocol": "TCP", "duration_ms": 1200, "packets": 220,
    "bytes_total": 120000, "tcp_syn_count": 90, "failed_logins": 0,
    "connections_last_minute": 300, "unique_ports_last_minute": 55,
}


@pytest.fixture()
def client(tmp_path: Path):
    original_store = main.store
    main.store = EventStore(tmp_path / "api.db")
    try:
        with TestClient(main.app) as test_client:
            yield test_client
    finally:
        main.store = original_store


def test_health_and_detection_contract(client: TestClient) -> None:
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["model_ready"] is True
    response = client.post("/api/detect", json=PAYLOAD)
    assert response.status_code == 201
    body = response.json()
    assert body["detection"]["attack_type"] == "Port Scan"
    assert body["detection"]["rule_hits"][0]["rule_id"] == "NET-001"
    status = client.patch(f"/api/events/{body['id']}/status", json={"status": "resolved"})
    assert status.status_code == 200
    assert status.json()["status"] == "resolved"


def test_api_rejects_invalid_flow(client: TestClient) -> None:
    invalid = {**PAYLOAD, "dst_port": 70000}
    assert client.post("/api/detect", json=invalid).status_code == 422
