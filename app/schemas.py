from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class NetworkFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP"]
    duration_ms: float = Field(ge=0, le=86_400_000)
    packets: int = Field(ge=1, le=10_000_000)
    bytes_total: int = Field(ge=0, le=100_000_000_000)
    tcp_syn_count: int = Field(default=0, ge=0)
    failed_logins: int = Field(default=0, ge=0, le=100_000)
    connections_last_minute: int = Field(default=1, ge=0, le=10_000_000)
    unique_ports_last_minute: int = Field(default=1, ge=0, le=65536)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        ip_address(value)
        return value


class RuleHit(BaseModel):
    rule_id: str
    label: str
    reason: str
    score: float = Field(ge=0, le=1)


class DetectionResult(BaseModel):
    is_alert: bool
    event_type: str
    severity: Severity
    risk_score: float = Field(ge=0, le=100)
    anomaly_score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    rule_hits: list[RuleHit]
    explanation: list[str]
    model_version: str


class SecurityEvent(BaseModel):
    id: int
    flow: NetworkFlow
    detection: DetectionResult
    status: EventStatus = EventStatus.NEW
    created_at: datetime


class StatusUpdate(BaseModel):
    status: EventStatus


class Metrics(BaseModel):
    total_flows: int
    total_alerts: int
    critical_alerts: int
    alerts_last_hour: int
    detection_rate: float
    average_risk: float
    by_event_type: dict[str, int]
    by_severity: dict[str, int]
    timeline: list[dict[str, int | str]]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    model_ready: bool
    database_ready: bool
    version: str
