from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings
from app.detector import HybridDetector
from app.schemas import NetworkFlow


@dataclass
class Confusion:
    true_positive: int = 0
    true_negative: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def total(self) -> int:
        return self.true_positive + self.true_negative + self.false_positive + self.false_negative

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else 0.0


def _value(row: dict[str, str], *names: str, default: str = "0") -> str:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return default


def row_to_flow(row: dict[str, str]) -> NetworkFlow:
    duration_us = float(_value(row, " Flow Duration", "Flow Duration"))
    packets = int(max(float(_value(row, " Total Fwd Packets", "Total Fwd Packets")), 1))
    bytes_total = int(max(float(_value(row, " Total Length of Fwd Packets", "Total Length of Fwd Packets")), 0))
    dst_port = int(max(min(float(_value(row, " Destination Port", "Destination Port")), 65535), 0))
    syn_count = int(max(float(_value(row, " SYN Flag Count", "SYN Flag Count")), 0))

    return NetworkFlow(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=49152,
        dst_port=dst_port,
        protocol="TCP",
        duration_ms=max(duration_us / 1000.0, 0.001),
        packets=packets,
        bytes_total=bytes_total,
        tcp_syn_count=syn_count,
        failed_logins=0,
        connections_last_minute=1,
        unique_ports_last_minute=1,
    )


def is_attack(row: dict[str, str]) -> bool:
    label = _value(row, " Label", "Label", default="").strip().upper()
    return label != "BENIGN"


def evaluate_csv(path: Path, detector: HybridDetector, limit: int | None = None) -> Confusion:
    confusion = Confusion()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            if limit is not None and index >= limit:
                break
            try:
                expected_attack = is_attack(row)
                predicted_alert = detector.predict(row_to_flow(row)).is_alert
            except (TypeError, ValueError):
                continue

            if expected_attack and predicted_alert:
                confusion.true_positive += 1
            elif expected_attack and not predicted_alert:
                confusion.false_negative += 1
            elif not expected_attack and predicted_alert:
                confusion.false_positive += 1
            else:
                confusion.true_negative += 1
    return confusion


def print_report(confusion: Confusion) -> None:
    print("CICIDS2017 binary detection evaluation")
    print(f"rows: {confusion.total:,}")
    print(f"tp: {confusion.true_positive:,}")
    print(f"tn: {confusion.true_negative:,}")
    print(f"fp: {confusion.false_positive:,}")
    print(f"fn: {confusion.false_negative:,}")
    print(f"precision: {confusion.precision:.4f}")
    print(f"recall: {confusion.recall:.4f}")
    print(f"f1: {confusion.f1:.4f}")
    print(f"false_positive_rate: {confusion.false_positive_rate:.4f}")
    print()
    print("Note: use date/host-level holdout splits before making final performance claims.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate AegisFlow against a labeled CICIDS2017 flow CSV")
    parser.add_argument("--csv", type=Path, required=True, help="CICIDS2017 MachineLearningCSV file")
    parser.add_argument("--model", type=Path, default=settings.model_path, help="Optional trained model bundle")
    parser.add_argument("--limit", type=int, help="Maximum number of rows to evaluate")
    args = parser.parse_args()

    detector = HybridDetector(model_path=args.model, seed=settings.random_seed)
    confusion = evaluate_csv(args.csv, detector, args.limit)
    if confusion.total == 0:
        raise SystemExit("No valid CICIDS2017 rows were evaluated")
    print_report(confusion)


if __name__ == "__main__":
    main()
