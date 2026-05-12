"""Inspect CICIoT2023 CSV files before model training.

This script validates the dataset columns, infers binary labels from file paths,
and writes a small cleaned sample in Sentinel-IoT live feature format. It does
not train a model and does not produce precision/recall/F1 metrics.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sentinel_iot.ml.ciciot2023_preprocessing import (  # noqa: E402
    CICIOT_TO_LIVE_FEATURES,
    REQUIRED_CICIOT_COLUMNS,
    infer_binary_label_from_path,
    transform_ciciot_frame,
)
from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA  # noqa: E402


DEFAULT_DATA_DIR = PROJECT_ROOT / "evaluation" / "datasets" / "CSV"
DEFAULT_REPORT = PROJECT_ROOT / "evaluation" / "results" / "ciciot2023_dataset_column_report.json"
DEFAULT_SAMPLE = PROJECT_ROOT / "evaluation" / "cases" / "ciciot2023_live_features_sample.csv"
DEFAULT_CHUNK_SIZE = 100_000
DEFAULT_SAMPLE_ROWS = 1000


def find_csv_files(data_dir: Path) -> list[Path]:
    if not data_dir.exists():
        raise FileNotFoundError(f"Dataset directory not found: {data_dir}")
    csv_files = sorted(data_dir.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under dataset directory: {data_dir}")
    return csv_files


def _count_dict(counter: Counter[str]) -> dict[str, int]:
    return {key: int(value) for key, value in sorted(counter.items())}


def inspect_csv_files(
    data_dir: Path,
    output_report: Path,
    output_sample: Path,
    chunk_size: int,
    sample_rows: int,
) -> dict:
    csv_files = find_csv_files(data_dir)
    total_rows = 0
    missing_columns: list[dict] = []
    label_counts: Counter[str] = Counter()
    binary_label_counts: Counter[str] = Counter()
    nan_counts: Counter[str] = Counter()
    inf_counts: Counter[str] = Counter()
    negative_counts: Counter[str] = Counter()
    cleaning_totals: Counter[str] = Counter()
    sample_parts: list[pd.DataFrame] = []
    file_summaries: list[dict] = []

    for csv_path in csv_files:
        header = pd.read_csv(csv_path, nrows=0)
        missing = [column for column in REQUIRED_CICIOT_COLUMNS if column not in header.columns]
        label = infer_binary_label_from_path(csv_path)
        label_name = "BenignTraffic" if label == 0 else "Attack"
        file_summary = {
            "file": str(csv_path),
            "missing_columns": missing,
            "rows": 0,
            "label": int(label),
            "label_source": "inferred_from_path",
            "status": "ok" if not missing else "missing_columns",
        }

        if missing:
            missing_columns.append({"file": str(csv_path), "missing_columns": missing})
            file_summaries.append(file_summary)
            continue

        for chunk in pd.read_csv(csv_path, usecols=REQUIRED_CICIOT_COLUMNS, chunksize=chunk_size):
            chunk_rows = len(chunk)
            total_rows += chunk_rows
            file_summary["rows"] += chunk_rows
            label_counts[label_name] += chunk_rows
            binary_label_counts[str(label)] += chunk_rows

            renamed = chunk[REQUIRED_CICIOT_COLUMNS].rename(columns=CICIOT_TO_LIVE_FEATURES)
            numeric = renamed[LIVE_FEATURE_SCHEMA].apply(pd.to_numeric, errors="coerce")
            inf_mask = numeric.apply(np.isinf)
            numeric_without_inf = numeric.replace([np.inf, -np.inf], np.nan)
            nan_mask = numeric_without_inf.isna()
            negative_mask = numeric_without_inf < 0

            for feature in LIVE_FEATURE_SCHEMA:
                nan_counts[feature] += int(nan_mask[feature].sum())
                inf_counts[feature] += int(inf_mask[feature].sum())
                negative_counts[feature] += int(negative_mask[feature].sum())

            current_sample_rows = sum(len(part) for part in sample_parts)
            if current_sample_rows < sample_rows:
                transformed, y, cleaning = transform_ciciot_frame(chunk, csv_path)
                cleaning_totals["input_rows"] += int(cleaning["input_rows"])
                cleaning_totals["dropped_nan_rows"] += int(cleaning["dropped_nan_rows"])
                cleaning_totals["dropped_inf_rows"] += int(cleaning["dropped_inf_rows"])
                cleaning_totals["dropped_negative_rows"] += int(cleaning["dropped_negative_rows"])
                cleaning_totals["output_rows"] += int(cleaning["output_rows"])

                if not transformed.empty:
                    sample = transformed.copy()
                    sample["label"] = y.astype(int)
                    sample_parts.append(sample)

        file_summaries.append(file_summary)

    sample_output = pd.DataFrame(columns=LIVE_FEATURE_SCHEMA + ["label"])
    if sample_parts:
        sample_output = pd.concat(sample_parts, ignore_index=True).head(sample_rows)

    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_sample.parent.mkdir(parents=True, exist_ok=True)
    sample_output.to_csv(output_sample, index=False)

    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data_dir": str(data_dir),
        "csv_count": len(csv_files),
        "total_rows": int(total_rows),
        "required_columns": REQUIRED_CICIOT_COLUMNS,
        "source_column_mapping": CICIOT_TO_LIVE_FEATURES,
        "missing_columns": missing_columns,
        "has_missing_columns": bool(missing_columns),
        "label_source": "inferred_from_path",
        "label_rule": "path_or_filename_contains_BenignTraffic_means_0_otherwise_1",
        "label_distribution": _count_dict(label_counts),
        "binary_label_distribution": _count_dict(binary_label_counts),
        "inferred_benign_count": int(binary_label_counts.get("0", 0)),
        "inferred_attack_count": int(binary_label_counts.get("1", 0)),
        "nan_counts": _count_dict(nan_counts),
        "inf_counts": _count_dict(inf_counts),
        "negative_counts": _count_dict(negative_counts),
        "has_nan_or_inf": any(nan_counts.values()) or any(inf_counts.values()),
        "sample_output": str(output_sample),
        "sample_rows_written": int(len(sample_output)),
        "sample_cleaning_summary": _count_dict(cleaning_totals),
        "final_feature_schema": LIVE_FEATURE_SCHEMA,
        "file_summaries": file_summaries,
        "scope": "schema_and_cleaning_inspection_only_no_model_training",
    }

    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect CICIoT2023 CSV schema for Sentinel-IoT.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output-sample", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--sample-rows", type=int, default=DEFAULT_SAMPLE_ROWS)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = inspect_csv_files(
        data_dir=args.data_dir,
        output_report=args.output_report,
        output_sample=args.output_sample,
        chunk_size=args.chunk_size,
        sample_rows=args.sample_rows,
    )
    print(json.dumps({
        "status": "ok",
        "csv_count": report["csv_count"],
        "total_rows": report["total_rows"],
        "has_missing_columns": report["has_missing_columns"],
        "has_nan_or_inf": report["has_nan_or_inf"],
        "sample_rows_written": report["sample_rows_written"],
        "output_report": str(args.output_report),
        "output_sample": str(args.output_sample),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
