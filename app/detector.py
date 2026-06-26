from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.schemas import DetectionResult, NetworkFlow, RuleHit, Severity


FEATURE_NAMES = (
    "duration_ms",
    "packets",
    "bytes_total",
    "bytes_per_packet",
    "packets_per_second",
    "dst_port",
    "tcp_syn_count",
    "failed_logins",
    "connections_last_minute",
    "unique_ports_last_minute",
)


@dataclass
class ModelBundle:
    scaler: StandardScaler
    model: IsolationForest
    version: str = "iforest-synthetic-v1"


def vectorize(flow: NetworkFlow) -> np.ndarray:
    duration_seconds = max(flow.duration_ms / 1000.0, 0.001)
    bytes_per_packet = flow.bytes_total / max(flow.packets, 1)
    packets_per_second = flow.packets / duration_seconds
    return np.array(
        [
            flow.duration_ms,
            flow.packets,
            flow.bytes_total,
            bytes_per_packet,
            packets_per_second,
            flow.dst_port,
            flow.tcp_syn_count,
            flow.failed_logins,
            flow.connections_last_minute,
            flow.unique_ports_last_minute,
        ],
        dtype=float,
    )


def generate_baseline(seed: int = 42, rows: int = 2500) -> np.ndarray:
    """Generate a deterministic benign baseline for an immediately runnable demo."""
    rng = np.random.default_rng(seed)
    duration = rng.lognormal(mean=5.5, sigma=1.0, size=rows).clip(2, 30_000)
    packets = rng.lognormal(mean=3.0, sigma=0.8, size=rows).clip(1, 1500)
    bytes_per_packet = rng.normal(620, 220, size=rows).clip(60, 1500)
    bytes_total = packets * bytes_per_packet
    packets_per_second = packets / np.maximum(duration / 1000, 0.001)
    common_ports = rng.choice([53, 80, 123, 443, 993, 3389], size=rows, p=[0.15, 0.18, 0.04, 0.52, 0.07, 0.04])
    syn_count = rng.poisson(1.2, size=rows).clip(0, 12)
    failed_logins = rng.binomial(2, 0.015, size=rows)
    connections = rng.poisson(8, size=rows).clip(1, 60)
    unique_ports = rng.poisson(1.5, size=rows).clip(1, 10)
    return np.column_stack(
        [duration, packets, bytes_total, bytes_per_packet, packets_per_second, common_ports,
         syn_count, failed_logins, connections, unique_ports]
    )


class HybridDetector:
    """Explainable signatures plus an unsupervised anomaly detector."""

    def __init__(self, model_path: Path | None = None, seed: int = 42) -> None:
        self.model_path = model_path
        self.seed = seed
        self.bundle = self._load_or_fit()

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    def _load_or_fit(self) -> ModelBundle:
        if self.model_path and self.model_path.exists():
            loaded = joblib.load(self.model_path)
            if isinstance(loaded, ModelBundle):
                return loaded
        return self.fit(generate_baseline(self.seed), persist=False, version="iforest-synthetic-v1")

    def fit(self, features: np.ndarray, persist: bool = True, version: str = "iforest-custom-v1") -> ModelBundle:
        if features.ndim != 2 or features.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected feature matrix with {len(FEATURE_NAMES)} columns")
        scaler = StandardScaler()
        scaled = scaler.fit_transform(features)
        model = IsolationForest(
            n_estimators=180,
            contamination=0.04,
            max_samples="auto",
            random_state=self.seed,
            n_jobs=-1,
        )
        model.fit(scaled)
        self.bundle = ModelBundle(scaler=scaler, model=model, version=version)
        if persist and self.model_path:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.bundle, self.model_path)
        return self.bundle

    def _anomaly_score(self, feature: np.ndarray) -> float:
        scaled = self.bundle.scaler.transform(feature.reshape(1, -1))
        raw = float(-self.bundle.model.score_samples(scaled)[0])
        # Isolation Forest scores normally land near 0.35-0.8. Map that band to 0-1.
        return float(np.clip((raw - 0.35) / 0.4, 0, 1))

    @staticmethod
    def _rules(flow: NetworkFlow) -> list[RuleHit]:
        hits: list[RuleHit] = []
        packets_per_second = flow.packets / max(flow.duration_ms / 1000, 0.001)
        if flow.unique_ports_last_minute >= 24 or (flow.tcp_syn_count >= 40 and flow.unique_ports_last_minute >= 12):
            hits.append(RuleHit(rule_id="NET-001", label="Port Scan", reason=f"{flow.unique_ports_last_minute} unique ports probed in one minute", score=0.78))
        if flow.failed_logins >= 8:
            hits.append(RuleHit(rule_id="AUTH-001", label="Brute Force", reason=f"{flow.failed_logins} failed logins observed", score=min(0.90, 0.76 + flow.failed_logins / 160)))
        if flow.connections_last_minute >= 900 or packets_per_second >= 5000:
            hits.append(RuleHit(rule_id="NET-002", label="DoS", reason=f"Burst rate: {flow.connections_last_minute} connections/min, {packets_per_second:.0f} packets/s", score=0.94))
        if flow.bytes_total >= 80_000_000 and flow.dst_port not in {80, 443}:
            hits.append(RuleHit(rule_id="DLP-001", label="Data Exfiltration", reason=f"Large uncommon-port transfer: {flow.bytes_total / 1_000_000:.1f} MB", score=0.82))
        if flow.dst_port in {4444, 5555, 6667, 31337}:
            hits.append(RuleHit(rule_id="C2-001", label="Command & Control", reason=f"Known high-risk destination port {flow.dst_port}", score=0.74))
        return hits

    def predict(self, flow: NetworkFlow) -> DetectionResult:
        feature = vectorize(flow)
        anomaly = self._anomaly_score(feature)
        hits = self._rules(flow)
        strongest_rule = max((hit.score for hit in hits), default=0.0)
        # Rule and anomaly values are prioritization signals, not calibrated probabilities.
        # A modest anomaly contribution prevents every obvious synthetic attack collapsing
        # into the same critical bucket, while anomaly-only findings keep useful separation.
        combined = 1 - (1 - strongest_rule) * (1 - anomaly * 0.35) if hits else anomaly * 0.75
        is_alert = bool(hits) or anomaly >= 0.64
        risk = round((combined if is_alert else anomaly * 0.55) * 100, 1)
        if risk >= 90:
            severity = Severity.CRITICAL
        elif risk >= 72:
            severity = Severity.HIGH
        elif risk >= 48:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        attack_type = max(hits, key=lambda hit: hit.score).label if hits else ("Anomalous Flow" if is_alert else "Benign")
        explanations = [hit.reason for hit in hits]
        if anomaly >= 0.64:
            explanations.append(f"Traffic shape differs from the benign baseline (anomaly {anomaly:.2f})")
        if not explanations:
            explanations.append("No signature matched; flow remains within the learned baseline")
        confidence = strongest_rule if hits else (anomaly if is_alert else 1 - anomaly)
        return DetectionResult(
            is_alert=is_alert,
            attack_type=attack_type,
            severity=severity,
            risk_score=risk,
            anomaly_score=round(anomaly, 4),
            confidence=round(float(np.clip(confidence, 0, 1)), 4),
            rule_hits=hits,
            explanation=explanations,
            model_version=self.bundle.version,
        )

    def predict_many(self, flows: Iterable[NetworkFlow]) -> list[DetectionResult]:
        return [self.predict(flow) for flow in flows]
