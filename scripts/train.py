from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings
from app.detector import FEATURE_NAMES, HybridDetector, generate_baseline


CICIDS_COLUMNS = {
    " Flow Duration": "duration_ms",
    "Flow Duration": "duration_ms",
    " Total Fwd Packets": "packets",
    "Total Fwd Packets": "packets",
    " Total Length of Fwd Packets": "bytes_total",
    "Total Length of Fwd Packets": "bytes_total",
    " Destination Port": "dst_port",
    "Destination Port": "dst_port",
    " SYN Flag Count": "tcp_syn_count",
    "SYN Flag Count": "tcp_syn_count",
}


def load_cicids_benign(path: Path, limit: int = 200_000) -> np.ndarray:
    rows: list[list[float]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            label = (row.get(" Label") or row.get("Label") or "").strip().upper()
            if label != "BENIGN":
                continue
            try:
                duration_us = float(row.get(" Flow Duration") or row.get("Flow Duration") or 0)
                packets = float(row.get(" Total Fwd Packets") or row.get("Total Fwd Packets") or 0)
                bytes_total = float(row.get(" Total Length of Fwd Packets") or row.get("Total Length of Fwd Packets") or 0)
                dst_port = float(row.get(" Destination Port") or row.get("Destination Port") or 0)
                syn = float(row.get(" SYN Flag Count") or row.get("SYN Flag Count") or 0)
                duration_ms = max(duration_us / 1000, 0.001)
                bpp = bytes_total / max(packets, 1)
                pps = packets / max(duration_ms / 1000, 0.001)
                values = [duration_ms, packets, bytes_total, bpp, pps, dst_port, syn, 0, 1, 1]
                if all(np.isfinite(values)):
                    rows.append(values)
            except (TypeError, ValueError):
                continue
            if len(rows) >= limit:
                break
    if len(rows) < 100:
        raise ValueError("At least 100 valid BENIGN CICIDS2017 rows are required")
    return np.asarray(rows, dtype=float)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the AegisFlow benign-baseline detector")
    parser.add_argument("--csv", type=Path, help="CICIDS2017 flow CSV (BENIGN rows are used)")
    parser.add_argument("--output", type=Path, default=settings.model_path)
    parser.add_argument("--limit", type=int, default=200_000)
    args = parser.parse_args()
    features = load_cicids_benign(args.csv, args.limit) if args.csv else generate_baseline(settings.random_seed)
    detector = HybridDetector(model_path=args.output, seed=settings.random_seed)
    detector.fit(features, persist=True, version="iforest-cicids2017-v1" if args.csv else "iforest-synthetic-v1")
    print(f"Saved {args.output} using {len(features):,} rows and {len(FEATURE_NAMES)} features")


if __name__ == "__main__":
    main()

