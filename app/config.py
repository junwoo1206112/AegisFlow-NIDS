from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    app_name: str = "AegisFlow NIDS"
    database_path: Path = Path(os.getenv("NIDS_DB_PATH", ROOT_DIR / "data" / "nids.db"))
    model_path: Path = Path(os.getenv("NIDS_MODEL_PATH", ROOT_DIR / "data" / "detector.joblib"))
    simulator_interval_seconds: float = float(os.getenv("NIDS_SIMULATOR_INTERVAL", "1.4"))
    max_events: int = int(os.getenv("NIDS_MAX_EVENTS", "5000"))
    random_seed: int = int(os.getenv("NIDS_RANDOM_SEED", "42"))


settings = Settings()

