"""Preprocess raw N-BaIoT CSV files into a labelled binary benchmark dataset."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from nbaiot_utils import (
    DEFAULT_PROCESSED_DATASET,
    RAW_NBAIOT_DIR,
    drop_index_like_columns,
    ensure_nbaiot_dirs,
    find_csv_files,
    infer_label_and_attack_type,
    infer_source_device,
    is_metadata_file,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT CSV dosyalarini binary benchmark datasetine donusturur.")
    parser.add_argument("--raw-dir", type=Path, default=RAW_NBAIOT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--max-rows-per-file", type=int, default=20000)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--chunk-size", type=int, default=100000)
    return parser


def read_sample(path: Path, max_rows: int, random_state: int, chunk_size: int) -> pd.DataFrame:
    reservoir = []
    rng_state = random_state
    try:
        iterator = pd.read_csv(path, chunksize=chunk_size)
        for chunk in iterator:
            if chunk.empty:
                continue
            reservoir.append(chunk)
            combined = pd.concat(reservoir, ignore_index=True)
            if len(combined) > max_rows:
                combined = combined.sample(n=max_rows, random_state=rng_state)
                rng_state += 1
            reservoir = [combined.reset_index(drop=True)]
    except Exception as exc:
        raise ValueError(f"{path} okunamadi: {exc}") from exc

    if not reservoir:
        raise ValueError(f"{path} bos.")

    return reservoir[0].reset_index(drop=True)


def preprocess_file(path: Path, raw_dir: Path, max_rows: int, random_state: int, chunk_size: int) -> tuple[pd.DataFrame, int]:
    label, attack_type = infer_label_and_attack_type(path)
    source_device = infer_source_device(path, raw_dir)

    df = read_sample(path, max_rows, random_state, chunk_size)
    df = drop_index_like_columns(df)
    numeric = df.select_dtypes(include=["number"]).copy()
    if numeric.empty:
        raise ValueError(f"{path} icinde numeric feature kolonu bulunamadi.")

    numeric = numeric.replace([np.inf, -np.inf], np.nan).dropna(axis=0, how="any")
    if numeric.empty:
        raise ValueError(f"{path} temizleme sonrasi bos kaldi.")

    numeric["label"] = label
    numeric["attack_type"] = attack_type
    numeric["source_file"] = path.name
    numeric["source_device"] = source_device
    return numeric, len(df) - len(numeric)


def main() -> int:
    args = build_parser().parse_args()
    if args.max_rows_per_file < 1:
        print("[HATA] --max-rows-per-file en az 1 olmali.")
        return 1
    if args.chunk_size < 1000:
        print("[HATA] --chunk-size en az 1000 olmali.")
        return 1

    try:
        ensure_nbaiot_dirs()
        files = [path for path in find_csv_files(args.raw_dir) if not is_metadata_file(path)]
        if not files:
            raise FileNotFoundError(f"Islenecek N-BaIoT trafik CSV dosyasi bulunamadi: {args.raw_dir}")

        frames = []
        dropped_rows = 0
        for index, path in enumerate(files, start=1):
            frame, dropped = preprocess_file(
                path,
                args.raw_dir,
                args.max_rows_per_file,
                args.random_state,
                args.chunk_size,
            )
            dropped_rows += dropped
            frames.append(frame)
            print(f"[{index}/{len(files)}] {path.name}: {len(frame)} satir")

        dataset = pd.concat(frames, ignore_index=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        dataset.to_csv(args.output, index=False)
    except Exception as exc:
        print(f"[HATA] N-BaIoT preprocessing basarisiz: {exc}")
        return 1

    feature_count = len([column for column in dataset.columns if column not in {"label", "attack_type", "source_file", "source_device"}])
    print("[OK] N-BaIoT preprocessing tamamlandi.")
    print(f"  Toplam satir: {len(dataset)}")
    print(f"  Toplam feature: {feature_count}")
    print(f"  Temizleme ile atilan satir: {dropped_rows}")
    print("  Label dagilimi:")
    print(dataset["label"].value_counts().sort_index().to_string())
    print("  Attack type dagilimi:")
    print(dataset["attack_type"].value_counts().to_string())
    print(f"  Cikti: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
