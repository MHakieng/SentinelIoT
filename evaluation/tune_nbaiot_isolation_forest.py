"""Tune Isolation Forest baseline on N-BaIoT processed dataset."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from nbaiot_utils import (
    DEFAULT_PROCESSED_DATASET,
    RESULTS_DIR,
    calculate_binary_metrics,
    ensure_nbaiot_dirs,
    load_processed_dataset,
)


CONTAMINATION_VALUES = [0.01, 0.03, 0.05, 0.10, 0.15, 0.20]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT Isolation Forest contamination tuning.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        x, y, _ = load_processed_dataset(args.dataset)
        normal_mask = y == 0
        if int(normal_mask.sum()) < 2:
            raise ValueError("Isolation Forest train icin en az 2 benign kayit gerekir. not enough data.")

        scaler = StandardScaler()
        x_train = scaler.fit_transform(x[normal_mask])
        x_all = scaler.transform(x)

        rows = []
        for contamination in CONTAMINATION_VALUES:
            model = IsolationForest(contamination=contamination, random_state=args.random_state)
            model.fit(x_train)
            raw_pred = model.predict(x_all)
            y_pred = np.where(raw_pred == -1, 1, 0)
            metrics = calculate_binary_metrics(y, y_pred)
            rows.append({"model": f"isolation_forest_{contamination}", "contamination": contamination, **metrics})
            print(f"[OK] contamination={contamination}: f1={metrics['f1_score']}")

        output = RESULTS_DIR / "nbaiot_isolation_forest_tuning.csv"
        pd.DataFrame(rows).to_csv(output, index=False)
    except Exception as exc:
        print(f"[HATA] Isolation Forest tuning basarisiz: {exc}")
        return 1

    print(f"[OK] Tuning raporu: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
