"""Validate N-BaIoT benchmark with device-disjoint train/test split."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from nbaiot_utils import (
    DEFAULT_PROCESSED_DATASET,
    RESULTS_DIR,
    TARGET_COLUMNS,
    calculate_binary_metrics,
    ensure_nbaiot_dirs,
    write_classification_report,
    write_confusion_matrix_png,
    write_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT device split benchmark.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        if not args.dataset.exists():
            raise FileNotFoundError(f"Processed dataset bulunamadi: {args.dataset}")
        df = pd.read_csv(args.dataset)
        if "source_device" not in df.columns:
            raise ValueError("source_device kolonu yok. Once preprocess_nbaiot.py calistirin.")

        devices = sorted(df["source_device"].dropna().astype(str).unique())
        if len(devices) < 2:
            raise ValueError("Device split icin en az 2 farkli source_device gerekir.")

        train_devices, test_devices = train_test_split(
            devices,
            test_size=args.test_size,
            random_state=args.random_state,
        )
        train_df = df[df["source_device"].isin(train_devices)].copy()
        test_df = df[df["source_device"].isin(test_devices)].copy()
        if train_df.empty or test_df.empty:
            raise ValueError("Device split sonrasi train veya test seti bos kaldi.")
        if train_df["label"].nunique() < 2 or test_df["label"].nunique() < 2:
            raise ValueError("Device split train/test setlerinde iki sinif da bulunmuyor. not enough data.")

        feature_columns = [
            column
            for column in df.columns
            if column not in TARGET_COLUMNS and pd.api.types.is_numeric_dtype(df[column])
        ]
        if not feature_columns:
            raise ValueError("Egitim icin numeric feature bulunamadi.")

        x_train = train_df[feature_columns].astype("float32")
        y_train = train_df["label"].astype(int)
        x_test = test_df[feature_columns].astype("float32")
        y_test = test_df["label"].astype(int)

        model = RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            n_jobs=-1,
            random_state=args.random_state,
        )
        print(f"[INFO] Device split RF egitiliyor: train_devices={len(train_devices)}, test_devices={len(test_devices)}")
        model.fit(x_train, y_train)
        y_pred = model.predict(x_test)
        metrics = calculate_binary_metrics(y_test, y_pred)

        summary = {
            "model": "random_forest_device_split",
            "dataset": str(args.dataset),
            "train_devices": list(train_devices),
            "test_devices": list(test_devices),
            "train_count": int(len(train_df)),
            "test_count": int(len(test_df)),
            "feature_count": len(feature_columns),
            "metrics": metrics,
        }
        write_json(RESULTS_DIR / "nbaiot_device_split_summary.json", summary)
        write_classification_report(y_test, y_pred, RESULTS_DIR / "nbaiot_device_split_classification_report.csv")
        write_confusion_matrix_png(
            y_test,
            y_pred,
            RESULTS_DIR / "nbaiot_device_split_confusion_matrix.png",
            "N-BaIoT Binary Classification Confusion Matrix",
        )
    except Exception as exc:
        print(f"[HATA] N-BaIoT device split basarisiz: {exc}")
        return 1

    print(f"[OK] Device split F1-score: {metrics['f1_score']}")
    print(f"[OK] Summary: {RESULTS_DIR / 'nbaiot_device_split_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
