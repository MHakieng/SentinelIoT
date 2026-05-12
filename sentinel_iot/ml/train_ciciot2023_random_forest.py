"""Train a CICIoT2023 RandomForest model for Sentinel-IoT live features."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from sentinel_iot.ml.ciciot2023_preprocessing import (
    CICIOT_TO_LIVE_FEATURES,
    REQUIRED_CICIOT_COLUMNS,
    infer_binary_label_from_path,
    transform_ciciot_frame,
)
from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = PROJECT_ROOT / "evaluation" / "datasets" / "CSV"
DEFAULT_MODEL = Path(__file__).resolve().parent / "models" / "ciciot2023_random_forest.joblib"
DEFAULT_REPORT = PROJECT_ROOT / "evaluation" / "results" / "ciciot2023_random_forest_report.json"
DEFAULT_CHUNK_SIZE = 100_000
DEFAULT_MAX_PER_CLASS = 300_000
LABEL_MAPPING = {"BenignTraffic": 0, "Attack": 1}


def find_csv_files(data_dir: Path) -> list[Path]:
    if not data_dir.exists():
        raise FileNotFoundError(f"CICIoT2023 data directory not found: {data_dir}")
    csv_files = sorted(data_dir.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No .csv files found under CICIoT2023 data directory: {data_dir}")
    return csv_files


def build_model_pipeline(random_state: int) -> Pipeline:
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            random_state=random_state,
            class_weight="balanced",
            n_jobs=-1,
            max_depth=None,
        )),
    ])


def _add_cleaning_totals(total: Counter[str], cleaning: dict[str, Any]) -> None:
    for key in ("input_rows", "dropped_nan_rows", "dropped_inf_rows", "dropped_negative_rows", "output_rows"):
        total[key] += int(cleaning.get(key, 0))


def _sample_chunk(
    frame: pd.DataFrame,
    label: int,
    target_total_rows: int,
    rows_seen_for_label: int,
    random_state: int,
    chunk_index: int,
) -> pd.DataFrame:
    if frame.empty or target_total_rows <= 0:
        return frame.head(0)

    # Deterministic distributed sampling across the full class stream. This
    # avoids taking only the first attack family in the sorted CSV tree.
    sample_fraction = min(1.0, target_total_rows / max(1, rows_seen_for_label))
    random_seed = random_state + (chunk_index * 17) + (label * 1_000_003)
    return frame.sample(frac=sample_fraction, random_state=random_seed) if sample_fraction < 1.0 else frame


def load_balanced_dataset(
    data_dir: Path,
    max_benign: int,
    max_attack: int,
    random_state: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[pd.DataFrame, pd.Series, dict[str, Any]]:
    csv_files = find_csv_files(data_dir)
    parts: list[pd.DataFrame] = []
    rows_seen_by_label: Counter[int] = Counter()
    rows_after_cleaning_by_label: Counter[int] = Counter()
    cleaning_totals: Counter[str] = Counter()
    missing_columns: list[dict[str, Any]] = []
    chunk_index = 0

    max_by_label = {0: max_benign, 1: max_attack}

    for csv_path in csv_files:
        header = pd.read_csv(csv_path, nrows=0)
        missing = [column for column in REQUIRED_CICIOT_COLUMNS if column not in header.columns]
        if missing:
            missing_columns.append({"file": str(csv_path), "missing_columns": missing})
            continue

        label = infer_binary_label_from_path(csv_path)
        for chunk in pd.read_csv(csv_path, usecols=REQUIRED_CICIOT_COLUMNS, chunksize=chunk_size):
            chunk_index += 1
            rows_seen_by_label[label] += len(chunk)
            x_clean, y_clean, cleaning = transform_ciciot_frame(chunk, csv_path)
            _add_cleaning_totals(cleaning_totals, cleaning)
            rows_after_cleaning_by_label[label] += len(x_clean)
            if x_clean.empty:
                continue

            labelled = x_clean.copy()
            labelled["label"] = y_clean.astype(int)
            sampled = _sample_chunk(
                labelled,
                label=label,
                target_total_rows=max_by_label[label],
                rows_seen_for_label=rows_seen_by_label[label],
                random_state=random_state,
                chunk_index=chunk_index,
            )
            if not sampled.empty:
                parts.append(sampled)

    if missing_columns:
        raise ValueError(f"CICIoT2023 CSV files are missing required columns: {missing_columns[:5]}")
    if not parts:
        raise ValueError("No cleaned CICIoT2023 rows were loaded.")

    dataset = pd.concat(parts, ignore_index=True)
    benign = dataset[dataset["label"] == 0]
    attack = dataset[dataset["label"] == 1]
    if benign.empty or attack.empty:
        raise ValueError("Balanced training requires both benign and attack rows.")

    benign = benign.sample(n=min(max_benign, len(benign)), random_state=random_state)
    attack = attack.sample(n=min(max_attack, len(attack)), random_state=random_state)
    dataset = pd.concat([benign, attack], ignore_index=True)
    dataset = dataset.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    x = dataset[LIVE_FEATURE_SCHEMA]
    y = dataset["label"].astype(int)
    summary = {
        "csv_count": len(csv_files),
        "rows_seen": int(sum(rows_seen_by_label.values())),
        "rows_seen_by_label": {str(k): int(v) for k, v in sorted(rows_seen_by_label.items())},
        "rows_after_cleaning_by_label": {str(k): int(v) for k, v in sorted(rows_after_cleaning_by_label.items())},
        "rows_used": int(len(dataset)),
        "benign_used": int((y == 0).sum()),
        "attack_used": int((y == 1).sum()),
        "max_benign": int(max_benign),
        "max_attack": int(max_attack),
        "cleaning": {key: int(value) for key, value in sorted(cleaning_totals.items())},
    }
    return x, y, summary


def _feature_importances(model: Pipeline) -> dict[str, float]:
    classifier = model.named_steps["classifier"]
    return {
        feature: float(importance)
        for feature, importance in zip(LIVE_FEATURE_SCHEMA, classifier.feature_importances_)
    }


def train_and_evaluate(
    data_dir: Path,
    output_model: Path,
    output_report: Path,
    max_benign: int,
    max_attack: int,
    test_size: float,
    random_state: int,
) -> dict[str, Any]:
    x, y, dataset_summary = load_balanced_dataset(
        data_dir=data_dir,
        max_benign=max_benign,
        max_attack=max_attack,
        random_state=random_state,
    )

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    model = build_model_pipeline(random_state=random_state)
    model.fit(x_train, y_train)
    y_pred = model.predict(x_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }

    report = {
        "dataset": "CICIoT2023",
        "model_type": "RandomForestClassifier",
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "source_column_mapping": CICIOT_TO_LIVE_FEATURES,
        "label_mapping": LABEL_MAPPING,
        "label_source": "inferred_from_path",
        "csv_count": dataset_summary["csv_count"],
        "rows_seen": dataset_summary["rows_seen"],
        "rows_used": dataset_summary["rows_used"],
        "benign_used": dataset_summary["benign_used"],
        "attack_used": dataset_summary["attack_used"],
        "train_size": int(len(x_train)),
        "test_size": int(len(x_test)),
        "metrics": metrics,
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(y_test, y_pred, zero_division=0, output_dict=True),
        "feature_importances": _feature_importances(model),
        "sampling": dataset_summary,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "note": "These are offline dataset validation metrics, not live runtime detection metrics.",
    }

    artifact = {
        "model": model,
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "label_mapping": LABEL_MAPPING,
        "dataset": "CICIoT2023",
        "model_type": "RandomForestClassifier",
    }

    output_model.parent.mkdir(parents=True, exist_ok=True)
    output_report.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_model)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train CICIoT2023 RandomForest model for Sentinel-IoT.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--output-report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--max-benign", type=int, default=DEFAULT_MAX_PER_CLASS)
    parser.add_argument("--max-attack", type=int, default=DEFAULT_MAX_PER_CLASS)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = train_and_evaluate(
        data_dir=args.data_dir,
        output_model=args.output_model,
        output_report=args.output_report,
        max_benign=args.max_benign,
        max_attack=args.max_attack,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    print(json.dumps({
        "status": "ok",
        "output_model": str(args.output_model),
        "output_report": str(args.output_report),
        "rows_used": report["rows_used"],
        "metrics": report["metrics"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
