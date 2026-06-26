from __future__ import annotations

import pytest

from app.detector import HybridDetector
from app.schemas import NetworkFlow, Severity


def flow(**overrides) -> NetworkFlow:
    values = {
        "src_ip": "10.20.1.10", "dst_ip": "198.51.100.21", "src_port": 49152,
        "dst_port": 443, "protocol": "TCP", "duration_ms": 500,
        "packets": 20, "bytes_total": 12_000, "tcp_syn_count": 1,
        "failed_logins": 0, "connections_last_minute": 8, "unique_ports_last_minute": 2,
    }
    values.update(overrides)
    return NetworkFlow(**values)


@pytest.fixture(scope="module")
def detector() -> HybridDetector:
    return HybridDetector(seed=42)


def test_benign_flow_is_not_alert(detector: HybridDetector) -> None:
    result = detector.predict(flow())
    assert not result.is_alert
    assert result.event_type == "Normal Flow"
    assert result.severity is Severity.LOW


@pytest.mark.parametrize(
    ("changes", "event_type"),
    [
        ({"unique_ports_last_minute": 70, "tcp_syn_count": 65}, "Abnormal Port Access"),
        ({"failed_logins": 18, "dst_port": 22}, "Repeated Access Failure"),
        ({"connections_last_minute": 1800, "packets": 30_000, "duration_ms": 1000}, "Connection Burst"),
        ({"bytes_total": 140_000_000, "dst_port": 9001}, "Large Data Transfer"),
        ({"dst_port": 4444}, "Suspicious Remote Port"),
    ],
)
def test_signature_events_are_detected(detector: HybridDetector, changes: dict, event_type: str) -> None:
    result = detector.predict(flow(**changes))
    assert result.is_alert
    assert result.event_type == event_type
    assert result.rule_hits
    assert result.risk_score >= 70


def test_invalid_ip_is_rejected() -> None:
    with pytest.raises(ValueError):
        flow(src_ip="999.10.10.10")
