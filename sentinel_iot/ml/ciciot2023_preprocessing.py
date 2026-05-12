"""CICIoT2023 preprocessing helpers for Sentinel-IoT live feature training."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np
import pandas as pd

from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA


CICIOT_TO_LIVE_FEATURES = {
    "Number": "packet_count",
    "Tot sum": "byte_count",
    "AVG": "avg_packet_size",
    "IAT": "mean_iat",
    "Variance": "var_iat",
    "Rate": "packet_rate",
}

REQUIRED_CICIOT_COLUMNS = list(CICIOT_TO_LIVE_FEATURES.keys())
NON_NEGATIVE_FEATURES = set(LIVE_FEATURE_SCHEMA)


def infer_binary_label_from_path(path: str | Path) -> int:
    """Infer binary label from CICIoT2023 file path.

    Benign files contain "BenignTraffic" in their file/folder path. Every other
    class folder/file is treated as attack traffic.
    """
    normalized = str(path)
    return 0 if "BenignTraffic" in normalized else 1


def clean_feature_frame(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Coerce, clean, and order live features.

    Inf values are converted to NaN. Rows with NaN or negative feature values are
    dropped because these sample/preprocessing artifacts should contain only
    directly usable rows.
    """
    missing = [feature for feature in LIVE_FEATURE_SCHEMA if feature not in df.columns]
    if missing:
        raise ValueError(f"Missing live feature(s): {missing}")

    features = df[LIVE_FEATURE_SCHEMA].apply(pd.to_numeric, errors="coerce")
    inf_mask = features.apply(np.isinf)
    features = features.replace([np.inf, -np.inf], np.nan)
    nan_mask = features.isna()
    negative_mask = features[list(NON_NEGATIVE_FEATURES)] < 0

    drop_mask = nan_mask.any(axis=1) | negative_mask.any(axis=1)
    cleaned = features.loc[~drop_mask, LIVE_FEATURE_SCHEMA].reset_index(drop=True)

    cleaning_summary = {
        "input_rows": int(len(df)),
        "dropped_nan_rows": int(nan_mask.any(axis=1).sum()),
        "dropped_inf_rows": int(inf_mask.any(axis=1).sum()),
        "dropped_negative_rows": int(negative_mask.any(axis=1).sum()),
        "output_rows": int(len(cleaned)),
        "nan_counts": {column: int(nan_mask[column].sum()) for column in LIVE_FEATURE_SCHEMA},
        "inf_counts": {column: int(inf_mask[column].sum()) for column in LIVE_FEATURE_SCHEMA},
        "negative_counts": {column: int(negative_mask[column].sum()) for column in LIVE_FEATURE_SCHEMA},
    }
    return cleaned, cleaning_summary


def transform_ciciot_frame(df: pd.DataFrame, source_path: str | Path) -> Tuple[pd.DataFrame, pd.Series, Dict[str, Any]]:
    """Transform a CICIoT2023 chunk into live features plus inferred binary label."""
    missing = [column for column in REQUIRED_CICIOT_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"Missing CICIoT2023 column(s) in {source_path}: {missing}")

    renamed = df[REQUIRED_CICIOT_COLUMNS].rename(columns=CICIOT_TO_LIVE_FEATURES)
    cleaned, cleaning_summary = clean_feature_frame(renamed)
    label = infer_binary_label_from_path(source_path)
    y = pd.Series([label] * len(cleaned), name="label", dtype=int)
    return cleaned, y, cleaning_summary


def validate_live_feature_schema(df: pd.DataFrame) -> None:
    """Ensure exact live feature order."""
    columns = list(df.columns)
    if columns != LIVE_FEATURE_SCHEMA:
        raise ValueError(f"Invalid live feature schema. Expected {LIVE_FEATURE_SCHEMA}, got {columns}")
