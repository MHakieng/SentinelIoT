"""Robust CICIoT2023 validation checks for Sentinel-IoT.

This script does not overwrite the production model artifact. It trains
temporary RandomForest models to compare row-level random split metrics against
stricter validation setups:

- group split by source CSV file
- attack-family holdout
- duplicate/leakage checks on the six live features
- label-shuffle sanity check
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

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
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sentinel_iot.ml.ciciot2023_preprocessing import (  # noqa: E402
    REQUIRED_CICIOT_COLUMNS,
    infer_binary_label_from_path,
    transform_ciciot_frame,
)
from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA  # noqa: E402


DEFAULT_DATA_DIR = PROJECT_ROOT / "evaluation" / "datasets" / "CSV"
DEFAULT_OUTPUT = PROJECT_ROOT / "evaluation" / "results" / "ciciot2023_robust_validation_report.json"
DEFAULT_CHUNK_SIZE = 100_000
DEFAULT_MAX_BENIGN = 80_000
DEFAULT_MAX_ATTACK = 80_000
DEFAULT_HOLDOUT_FAMILIES = ["Mirai", "Recon", "Spoofing", "Web", "BruteForce"]


def find_csv_files(data_dir: Path) -> list[Path]:
    if not data_dir.exists():
        raise FileNotFoundError(f"CICIoT2023 data directory not found: {data_dir}")
    csv_files = sorted(data_dir.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under: {data_dir}")
    return csv_files


def infer_attack_family(path: str | Path) -> str:
    text = str(path)
    folder = Path(path).parent.name
    if "BenignTraffic" in text or folder == "Benign_Final":
        return "BenignTraffic"
    if folder.startswith("DDoS-"):
        return "DDoS"
    if folder.startswith("DoS-"):
        return "DoS"
    if folder.startswith("Recon-") or folder == "VulnerabilityScan":
        return "Recon"
    if "Spoofing" in folder:
        return "Spoofing"
    if folder.startswith("Mirai-"):
        return "Mirai"
    if folder in {"BrowserHijacking", "CommandInjection", "SqlInjection", "Uploading_Attack", "XSS"}:
        return "Web"
    if folder == "DictionaryBruteForce":
        return "BruteForce"
    if "Malware" in folder:
        return "Malware"
    return folder or "Unknown"


def build_model(random_state: int) -> Pipeline:
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


def evaluate_predictions(y_true, y_pred) -> dict[str, Any]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": classification_report(y_true, y_pred, zero_division=0, output_dict=True),
    }


def fit_and_score(x_train, x_test, y_train, y_test, random_state: int) -> dict[str, Any]:
    model = build_model(random_state)
    model.fit(x_train, y_train)
    y_pred = model.predict(x_test)
    return evaluate_predictions(y_test, y_pred)


def _sample_chunk(frame: pd.DataFrame, label: int, target_rows: int, rows_seen: int, random_state: int, chunk_index: int) -> pd.DataFrame:
    if frame.empty or target_rows <= 0:
        return frame.head(0)
    fraction = min(1.0, target_rows / max(1, rows_seen))
    seed = random_state + chunk_index * 31 + label * 1_000_003
    return frame.sample(frac=fraction, random_state=seed) if fraction < 1.0 else frame


def load_sampled_dataset(
    data_dir: Path,
    max_benign: int,
    max_attack: int,
    random_state: int,
    chunk_size: int,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    csv_files = find_csv_files(data_dir)
    rows_seen: Counter[int] = Counter()
    family_counts_seen: Counter[str] = Counter()
    sampled_parts: list[pd.DataFrame] = []
    missing_columns: list[dict[str, Any]] = []
    cleaning_totals: Counter[str] = Counter()
    chunk_index = 0
    max_by_label = {0: max_benign, 1: max_attack}

    for csv_path in csv_files:
        header = pd.read_csv(csv_path, nrows=0)
        missing = [column for column in REQUIRED_CICIOT_COLUMNS if column not in header.columns]
        if missing:
            missing_columns.append({"file": str(csv_path), "missing_columns": missing})
            continue

        label = infer_binary_label_from_path(csv_path)
        family = infer_attack_family(csv_path)

        for chunk in pd.read_csv(csv_path, usecols=REQUIRED_CICIOT_COLUMNS, chunksize=chunk_size):
            chunk_index += 1
            rows_seen[label] += len(chunk)
            family_counts_seen[family] += len(chunk)
            x_clean, y_clean, cleaning = transform_ciciot_frame(chunk, csv_path)
            for key in ("input_rows", "dropped_nan_rows", "dropped_inf_rows", "dropped_negative_rows", "output_rows"):
                cleaning_totals[key] += int(cleaning.get(key, 0))
            if x_clean.empty:
                continue

            labelled = x_clean.copy()
            labelled["label"] = y_clean.astype(int)
            labelled["source_file"] = str(csv_path)
            labelled["attack_family"] = family
            sampled = _sample_chunk(
                labelled,
                label=label,
                target_rows=max_by_label[label],
                rows_seen=rows_seen[label],
                random_state=random_state,
                chunk_index=chunk_index,
            )
            if not sampled.empty:
                sampled_parts.append(sampled)

    if missing_columns:
        raise ValueError(f"Missing required columns in CICIoT2023 files: {missing_columns[:5]}")
    if not sampled_parts:
        raise ValueError("No sampled rows were loaded.")

    dataset = pd.concat(sampled_parts, ignore_index=True)
    benign = dataset[dataset["label"] == 0]
    attack = dataset[dataset["label"] == 1]
    if benign.empty or attack.empty:
        raise ValueError("Both benign and attack samples are required.")

    benign = benign.sample(n=min(max_benign, len(benign)), random_state=random_state)
    attack = attack.sample(n=min(max_attack, len(attack)), random_state=random_state)
    dataset = pd.concat([benign, attack], ignore_index=True)
    dataset = dataset.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    summary = {
        "csv_count": len(csv_files),
        "rows_seen_by_label": {str(k): int(v) for k, v in sorted(rows_seen.items())},
        "rows_used": int(len(dataset)),
        "benign_used": int((dataset["label"] == 0).sum()),
        "attack_used": int((dataset["label"] == 1).sum()),
        "family_counts_seen": {k: int(v) for k, v in sorted(family_counts_seen.items())},
        "family_counts_used": {k: int(v) for k, v in sorted(dataset["attack_family"].value_counts().items())},
        "cleaning": {k: int(v) for k, v in sorted(cleaning_totals.items())},
    }
    return dataset, summary


def duplicate_report(dataset: pd.DataFrame) -> dict[str, Any]:
    feature_duplicates = dataset.duplicated(subset=LIVE_FEATURE_SCHEMA, keep=False)
    duplicate_rows = int(feature_duplicates.sum())
    duplicate_vectors = int(dataset.loc[feature_duplicates, LIVE_FEATURE_SCHEMA].drop_duplicates().shape[0])
    return {
        "rows": int(len(dataset)),
        "duplicate_rows_on_features": duplicate_rows,
        "duplicate_row_ratio_on_features": float(duplicate_rows / max(1, len(dataset))),
        "duplicate_feature_vectors": duplicate_vectors,
    }


def train_test_duplicate_overlap(x_train: pd.DataFrame, x_test: pd.DataFrame) -> dict[str, Any]:
    train_vectors = set(map(tuple, x_train[LIVE_FEATURE_SCHEMA].itertuples(index=False, name=None)))
    test_vectors = set(map(tuple, x_test[LIVE_FEATURE_SCHEMA].itertuples(index=False, name=None)))
    overlap = train_vectors.intersection(test_vectors)
    return {
        "train_unique_vectors": len(train_vectors),
        "test_unique_vectors": len(test_vectors),
        "overlap_unique_vectors": len(overlap),
        "overlap_ratio_vs_test_unique": float(len(overlap) / max(1, len(test_vectors))),
    }


def random_split_validation(dataset: pd.DataFrame, test_size: float, random_state: int) -> dict[str, Any]:
    x = dataset[LIVE_FEATURE_SCHEMA]
    y = dataset["label"].astype(int)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=test_size, random_state=random_state, stratify=y)
    result = fit_and_score(x_train, x_test, y_train, y_test, random_state)
    result["train_size"] = int(len(x_train))
    result["test_size"] = int(len(x_test))
    result["train_test_duplicate_overlap"] = train_test_duplicate_overlap(x_train, x_test)
    return result


def group_split_validation(dataset: pd.DataFrame, test_size: float, random_state: int) -> dict[str, Any]:
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    groups = dataset["source_file"]
    train_idx, test_idx = next(splitter.split(dataset[LIVE_FEATURE_SCHEMA], dataset["label"], groups=groups))
    train = dataset.iloc[train_idx]
    test = dataset.iloc[test_idx]
    result = fit_and_score(train[LIVE_FEATURE_SCHEMA], test[LIVE_FEATURE_SCHEMA], train["label"].astype(int), test["label"].astype(int), random_state)
    result["train_size"] = int(len(train))
    result["test_size"] = int(len(test))
    result["train_source_files"] = int(train["source_file"].nunique())
    result["test_source_files"] = int(test["source_file"].nunique())
    result["source_file_overlap"] = sorted(set(train["source_file"]).intersection(set(test["source_file"])))
    result["train_test_duplicate_overlap"] = train_test_duplicate_overlap(train[LIVE_FEATURE_SCHEMA], test[LIVE_FEATURE_SCHEMA])
    return result


def attack_family_holdout_validation(dataset: pd.DataFrame, holdout_families: list[str], random_state: int) -> dict[str, Any]:
    holdout_set = set(holdout_families)
    train = dataset[(dataset["label"] == 0) | (~dataset["attack_family"].isin(holdout_set))]
    test = dataset[(dataset["label"] == 0) | (dataset["attack_family"].isin(holdout_set))]
    # Keep the benign test subset bounded and deterministic so attack holdout metrics are not dominated by benign rows.
    test_benign = test[test["label"] == 0]
    test_attack = test[test["label"] == 1]
    if len(test_benign) > len(test_attack) and len(test_attack) > 0:
        test_benign = test_benign.sample(n=len(test_attack), random_state=random_state)
        test = pd.concat([test_benign, test_attack], ignore_index=True).sample(frac=1.0, random_state=random_state)

    if train["label"].nunique() < 2 or test["label"].nunique() < 2:
        raise ValueError(
            "Attack-family holdout requires both labels in train/test. "
            f"Holdout families present: {sorted(test_attack['attack_family'].unique())}"
        )

    result = fit_and_score(train[LIVE_FEATURE_SCHEMA], test[LIVE_FEATURE_SCHEMA], train["label"].astype(int), test["label"].astype(int), random_state)
    result["holdout_families_requested"] = holdout_families
    result["holdout_families_present"] = sorted(test_attack["attack_family"].unique())
    result["train_size"] = int(len(train))
    result["test_size"] = int(len(test))
    result["test_family_counts"] = {k: int(v) for k, v in sorted(test["attack_family"].value_counts().items())}
    result["train_test_duplicate_overlap"] = train_test_duplicate_overlap(train[LIVE_FEATURE_SCHEMA], test[LIVE_FEATURE_SCHEMA])
    return result


def label_shuffle_validation(dataset: pd.DataFrame, test_size: float, random_state: int) -> dict[str, Any]:
    shuffled = dataset.copy()
    shuffled["label"] = shuffled["label"].sample(frac=1.0, random_state=random_state + 991).reset_index(drop=True).astype(int)
    return random_split_validation(shuffled, test_size=test_size, random_state=random_state)


def run_validation(
    data_dir: Path,
    output_report: Path,
    max_benign: int,
    max_attack: int,
    test_size: float,
    random_state: int,
    holdout_families: list[str],
    chunk_size: int,
) -> dict[str, Any]:
    dataset, dataset_summary = load_sampled_dataset(
        data_dir=data_dir,
        max_benign=max_benign,
        max_attack=max_attack,
        random_state=random_state,
        chunk_size=chunk_size,
    )

    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CICIoT2023",
        "model_type": "RandomForestClassifier",
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "label_source": "inferred_from_path",
        "sample_summary": dataset_summary,
        "duplicate_report": duplicate_report(dataset),
        "original_random_split_metrics": random_split_validation(dataset, test_size, random_state),
        "group_by_file_split_metrics": group_split_validation(dataset, test_size, random_state),
        "attack_family_holdout_metrics": attack_family_holdout_validation(dataset, holdout_families, random_state),
        "label_shuffle_sanity_metrics": label_shuffle_validation(dataset, test_size, random_state),
        "note": "These are offline validation checks, not live runtime detection metrics.",
    }

    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run robust CICIoT2023 validation checks.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-report", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-benign", type=int, default=DEFAULT_MAX_BENIGN)
    parser.add_argument("--max-attack", type=int, default=DEFAULT_MAX_ATTACK)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--holdout-families", nargs="*", default=DEFAULT_HOLDOUT_FAMILIES)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_validation(
        data_dir=args.data_dir,
        output_report=args.output_report,
        max_benign=args.max_benign,
        max_attack=args.max_attack,
        test_size=args.test_size,
        random_state=args.random_state,
        holdout_families=args.holdout_families,
        chunk_size=args.chunk_size,
    )
    print(json.dumps({
        "status": "ok",
        "output_report": str(args.output_report),
        "rows_used": report["sample_summary"]["rows_used"],
        "random_split_f1": report["original_random_split_metrics"]["f1"],
        "group_split_f1": report["group_by_file_split_metrics"]["f1"],
        "attack_holdout_f1": report["attack_family_holdout_metrics"]["f1"],
        "label_shuffle_f1": report["label_shuffle_sanity_metrics"]["f1"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
