"""Train a CICIoT2023 RandomForest model on Sentinel-IoT live-flow features.

This module intentionally reports only metrics computed from the provided CSV
dataset. It does not create runtime/live detection metrics.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA


CICIOT_COLUMN_MAPPING = {
    "Number": "packet_count",
    "Tot sum": "byte_count",
    "flow_duration": "duration",
    "AVG": "avg_packet_size",
    "IAT": "mean_iat",
    "Variance": "var_iat",
}

LABEL_COLUMN = "label"
REQUIRED_COLUMNS = list(CICIOT_COLUMN_MAPPING.keys()) + [LABEL_COLUMN]
LABEL_MAPPING = {"BenignTraffic": 0, "Attack": 1}
DEFAULT_CHUNKSIZE = 100_000


def find_csv_files(data_dir: str | Path) -> List[Path]:
    data_path = Path(data_dir)
    if not data_path.exists():
        raise FileNotFoundError(f"CICIoT2023 data directory not found: {data_path}")
    csv_files = sorted(data_path.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No .csv files found under CICIoT2023 data directory: {data_path}")
    return csv_files


def validate_csv_columns(csv_path: Path) -> None:
    header = pd.read_csv(csv_path, nrows=0)
    missing = [column for column in REQUIRED_COLUMNS if column not in header.columns]
    if missing:
        raise ValueError(
            f"Missing required CICIoT2023 column(s) in {csv_path}: {missing}. "
            f"Required columns: {REQUIRED_COLUMNS}"
        )


def transform_ciciot_frame(frame: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, Dict[str, int]]:
    """Normalize CICIoT2023 columns into Sentinel-IoT's live feature schema."""
    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing required CICIoT2023 column(s): {missing}")

    working = frame[REQUIRED_COLUMNS].rename(columns=CICIOT_COLUMN_MAPPING).copy()
    labels = working.pop(LABEL_COLUMN).astype(str)
    y = labels.ne("BenignTraffic").astype(int)

    X = working[LIVE_FEATURE_SCHEMA].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    negative_mask = (X < 0).any(axis=1)
    nan_mask = X.isna().any(axis=1)
    keep_mask = ~(negative_mask | nan_mask)

    cleaning_summary = {
        "input_rows": int(len(frame)),
        "dropped_negative_rows": int(negative_mask.sum()),
        "dropped_nan_or_inf_rows": int((nan_mask & ~negative_mask).sum()),
        "output_rows": int(keep_mask.sum()),
    }

    return X.loc[keep_mask, LIVE_FEATURE_SCHEMA].reset_index(drop=True), y.loc[keep_mask].reset_index(drop=True), cleaning_summary


def _balanced_sample(frame: pd.DataFrame, sample_size: int, random_state: int) -> pd.DataFrame:
    if sample_size <= 0 or len(frame) <= sample_size:
        return frame

    benign = frame[frame[LABEL_COLUMN].astype(str).eq("BenignTraffic")]
    attack = frame[~frame[LABEL_COLUMN].astype(str).eq("BenignTraffic")]
    half = sample_size // 2

    benign_n = min(len(benign), half)
    attack_n = min(len(attack), sample_size - benign_n)

    sampled_parts = []
    if benign_n > 0:
        sampled_parts.append(benign.sample(n=benign_n, random_state=random_state))
    if attack_n > 0:
        sampled_parts.append(attack.sample(n=attack_n, random_state=random_state))

    remaining = sample_size - sum(len(part) for part in sampled_parts)
    if remaining > 0:
        used_index = pd.Index([])
        for part in sampled_parts:
            used_index = used_index.union(part.index)
        pool = frame.drop(index=used_index, errors="ignore")
        if len(pool) > 0:
            sampled_parts.append(pool.sample(n=min(remaining, len(pool)), random_state=random_state))

    return pd.concat(sampled_parts, ignore_index=True).sample(frac=1.0, random_state=random_state)


def load_ciciot2023_dataset(
    data_dir: str | Path,
    sample_size: int | None = None,
    random_state: int = 42,
    chunksize: int = DEFAULT_CHUNKSIZE,
) -> Tuple[pd.DataFrame, pd.Series, Dict[str, object]]:
    """Load selected CICIoT2023 CSV columns with optional balanced sampling."""
    csv_files = find_csv_files(data_dir)
    for csv_file in csv_files:
        validate_csv_columns(csv_file)

    raw_parts: List[pd.DataFrame] = []
    total_rows_seen = 0

    for csv_file in csv_files:
        for chunk in pd.read_csv(csv_file, usecols=REQUIRED_COLUMNS, chunksize=chunksize):
            total_rows_seen += len(chunk)
            if sample_size:
                # Keep bounded per-chunk candidates before the final balanced sample.
                per_chunk_limit = max(1_000, min(sample_size, chunksize))
                raw_parts.append(_balanced_sample(chunk, per_chunk_limit, random_state))
            else:
                raw_parts.append(chunk)

    if not raw_parts:
        raise ValueError(f"No CICIoT2023 rows loaded from: {data_dir}")

    raw = pd.concat(raw_parts, ignore_index=True)
    if sample_size:
        raw = _balanced_sample(raw, sample_size, random_state)

    X, y, cleaning = transform_ciciot_frame(raw)
    if len(X) < 2 or y.nunique() < 2:
        raise ValueError(
            "CICIoT2023 training data must contain at least two cleaned rows "
            "and both binary classes (BenignTraffic and attack labels)."
        )

    dataset_summary = {
        "data_dir": str(Path(data_dir)),
        "csv_file_count": len(csv_files),
        "csv_files": [str(path) for path in csv_files],
        "rows_seen": int(total_rows_seen),
        "rows_loaded_before_cleaning": int(len(raw)),
        "rows_after_cleaning": int(len(X)),
        "sample_size_requested": sample_size,
        "class_counts": {str(key): int(value) for key, value in y.value_counts().sort_index().items()},
        "cleaning": cleaning,
    }
    return X, y, dataset_summary


def build_model_pipeline(random_state: int) -> Pipeline:
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            random_state=random_state,
            class_weight="balanced",
            n_jobs=-1,
        )),
    ])


def _feature_importances(model: Pipeline) -> Dict[str, float]:
    classifier = model.named_steps["classifier"]
    importances = getattr(classifier, "feature_importances_", None)
    if importances is None:
        return {}
    return {
        feature: float(importance)
        for feature, importance in zip(LIVE_FEATURE_SCHEMA, importances)
    }


def train_and_evaluate(
    data_dir: str | Path,
    output_model: str | Path,
    output_report: str | Path,
    sample_size: int | None = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict[str, object]:
    X, y, dataset_summary = load_ciciot2023_dataset(
        data_dir=data_dir,
        sample_size=sample_size,
        random_state=random_state,
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    model = build_model_pipeline(random_state=random_state)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    metrics = {
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
    }

    report = {
        "dataset_summary": dataset_summary,
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "source_column_mapping": CICIOT_COLUMN_MAPPING,
        "label_mapping": LABEL_MAPPING,
        "model_type": "RandomForestClassifier",
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "metrics": metrics,
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(y_test, y_pred, zero_division=0, output_dict=True),
        "feature_importances": _feature_importances(model),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "validation_scope": "offline_ciciot2023_dataset_validation",
        "runtime_metrics": None,
    }

    output_model = Path(output_model)
    output_report = Path(output_report)
    output_model.parent.mkdir(parents=True, exist_ok=True)
    output_report.parent.mkdir(parents=True, exist_ok=True)

    artifact = {
        "model": model,
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "label_mapping": LABEL_MAPPING,
        "dataset": "CICIoT2023",
        "model_name": "ciciot2023_random_forest",
    }
    joblib.dump(artifact, output_model)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train Sentinel-IoT CICIoT2023 RandomForest model.")
    parser.add_argument("--data-dir", required=True, help="Directory containing CICIoT2023 CSV files.")
    parser.add_argument(
        "--output-model",
        default=str(Path(__file__).resolve().parent / "models" / "ciciot2023_random_forest.joblib"),
        help="Output .joblib model artifact path.",
    )
    parser.add_argument(
        "--output-report",
        default=str(Path(__file__).resolve().parents[2] / "evaluation" / "reports" / "ciciot2023_random_forest_report.json"),
        help="Output JSON report path.",
    )
    parser.add_argument("--sample-size", type=int, default=None, help="Optional approximate balanced sample size.")
    parser.add_argument("--test-size", type=float, default=0.2, help="Train/test split test size.")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    report = train_and_evaluate(
        data_dir=args.data_dir,
        output_model=args.output_model,
        output_report=args.output_report,
        sample_size=args.sample_size,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    print(json.dumps({
        "status": "ok",
        "output_model": args.output_model,
        "output_report": args.output_report,
        "metrics": report["metrics"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

