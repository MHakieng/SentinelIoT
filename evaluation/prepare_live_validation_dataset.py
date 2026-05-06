"""Convert manually labelled live flow snapshots to Sentinel-IoT validation CSV format."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "evaluation" / "live" / "live_flow_snapshots.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "evaluation" / "live" / "live_validation_dataset.csv"
FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "avg_packet_size",
    "mean_iat",
    "var_iat",
]
OUTPUT_COLUMNS = [*FEATURE_COLUMNS, "label", "attack_type"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Canli flow snapshotlarini validation dataset formatina cevirir.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--allow-unlabelled",
        action="store_true",
        help="Etiketsiz satirlari label=0 normal kabul eder. Demo disinda dikkatli kullanin.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if not args.input.exists():
            raise FileNotFoundError(f"Canli snapshot CSV bulunamadi: {args.input}")
        df = pd.read_csv(args.input)
        missing = [column for column in [*FEATURE_COLUMNS, "manual_label"] if column not in df.columns]
        if missing:
            raise ValueError(f"Input CSV eksik kolonlara sahip: {', '.join(missing)}")
        if df.empty:
            raise ValueError("Input CSV bos. Once collect_live_flows.py ile veri toplayin.")

        labels = df["manual_label"]
        if not args.allow_unlabelled and labels.isna().any():
            raise ValueError("manual_label bos satirlar var. 0=normal veya 1=anomaly olarak doldurun.")

        output = df[FEATURE_COLUMNS].copy()
        output = output.apply(pd.to_numeric, errors="coerce")
        if output.isna().any().any():
            bad_columns = output.columns[output.isna().any()].tolist()
            raise ValueError(f"Feature kolonlarinda eksik/bozuk sayisal veri var: {', '.join(bad_columns)}")
        if not np.isfinite(output.to_numpy(dtype=float)).all():
            raise ValueError("Feature kolonlarinda inf/gecersiz deger var.")

        if args.allow_unlabelled:
            output["label"] = labels.fillna(0).replace("", 0).astype(int)
        else:
            output["label"] = labels.astype(int)

        invalid_labels = sorted(set(output["label"].unique()) - {0, 1})
        if invalid_labels:
            raise ValueError(f"manual_label sadece 0 veya 1 olabilir. Gecersiz: {invalid_labels}")

        attack_type = df.get("attack_type", pd.Series([""] * len(df))).fillna("").replace("", "manual_live")
        output["attack_type"] = attack_type
        args.output.parent.mkdir(parents=True, exist_ok=True)
        output[OUTPUT_COLUMNS].to_csv(args.output, index=False)
    except Exception as exc:
        print(f"[HATA] Canli validation dataset hazirlanamadi: {exc}")
        return 1

    print(f"[OK] Canli validation dataset yazildi: {args.output}")
    print("Label dagilimi:")
    print(output["label"].value_counts().sort_index().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
