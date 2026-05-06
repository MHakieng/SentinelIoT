"""Inspect raw N-BaIoT CSV files and write a compact summary report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from nbaiot_utils import (
    RAW_NBAIOT_DIR,
    RESULTS_DIR,
    ensure_nbaiot_dirs,
    find_csv_files,
    infer_label_and_attack_type,
    is_metadata_file,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT raw CSV dosyalarini inceler.")
    parser.add_argument("--raw-dir", type=Path, default=RAW_NBAIOT_DIR)
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULTS_DIR / "nbaiot_inspection_summary.csv",
    )
    return parser


def inspect_file(path: Path) -> dict:
    label, attack_type = infer_label_and_attack_type(path)
    try:
        header = pd.read_csv(path, nrows=0)
        sample = pd.read_csv(path, nrows=1000)
    except Exception as exc:
        raise ValueError(f"{path} okunamadi: {exc}") from exc

    row_count = sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore")) - 1
    row_count = max(row_count, 0)
    missing_ratio = float(sample.isna().sum().sum() / sample.size) if sample.size else 0.0

    return {
        "file_name": path.name,
        "relative_path": str(path),
        "row_count": row_count,
        "column_count": len(header.columns),
        "first_10_columns": "|".join(str(column) for column in header.columns[:10]),
        "label": label,
        "attack_type": attack_type,
        "missing_value_ratio_sample": round(missing_ratio, 6),
        "included_for_preprocessing": not is_metadata_file(path),
    }


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        files = find_csv_files(args.raw_dir)
        rows = [inspect_file(path) for path in files]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(args.output, index=False)
    except Exception as exc:
        print(f"[HATA] N-BaIoT inspection basarisiz: {exc}")
        return 1

    print(f"[OK] {len(rows)} CSV dosyasi incelendi.")
    print(f"[OK] Rapor: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
