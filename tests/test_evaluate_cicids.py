from __future__ import annotations

from pathlib import Path

from app.detector import HybridDetector
from scripts.evaluate_cicids import evaluate_csv, row_to_flow


def test_row_to_flow_maps_cicids_columns() -> None:
    flow = row_to_flow(
        {
            " Destination Port": "443",
            " Flow Duration": "1000000",
            " Total Fwd Packets": "10",
            " Total Length of Fwd Packets": "5000",
            " SYN Flag Count": "2",
            " Label": "BENIGN",
        }
    )

    assert flow.dst_port == 443
    assert flow.duration_ms == 1000
    assert flow.packets == 10
    assert flow.bytes_total == 5000
    assert flow.tcp_syn_count == 2


def test_evaluate_csv_reports_confusion_counts(tmp_path: Path) -> None:
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text(
        "\n".join(
            [
                " Destination Port, Flow Duration, Total Fwd Packets, Total Length of Fwd Packets, SYN Flag Count, Label",
                "443,1000000,10,5000,1,BENIGN",
                "4444,200000,20,8000,5,Bot",
            ]
        ),
        encoding="utf-8",
    )

    confusion = evaluate_csv(csv_path, HybridDetector(seed=7))

    assert confusion.total == 2
    assert confusion.true_positive + confusion.false_negative == 1
    assert confusion.true_negative + confusion.false_positive == 1
