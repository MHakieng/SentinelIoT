"""Shared helpers for N-BaIoT evaluation scripts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_DIR = PROJECT_ROOT / "evaluation"
RAW_NBAIOT_DIR = EVALUATION_DIR / "datasets" / "raw" / "n_baiot"
PROCESSED_DIR = EVALUATION_DIR / "datasets" / "processed"
RESULTS_DIR = EVALUATION_DIR / "results"
MODELS_DIR = EVALUATION_DIR / "models"
DEFAULT_PROCESSED_DATASET = PROCESSED_DIR / "nbaiot_binary.csv"

METADATA_FILES = {"data_summary.csv", "device_info.csv", "features.csv"}
TARGET_COLUMNS = {"label", "attack_type", "source_file", "source_device"}


def ensure_nbaiot_dirs() -> None:
    for path in [RAW_NBAIOT_DIR, PROCESSED_DIR, RESULTS_DIR, MODELS_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def find_csv_files(raw_dir: Path) -> list[Path]:
    if not raw_dir.exists():
        raise FileNotFoundError(f"N-BaIoT raw klasoru bulunamadi: {raw_dir}")

    files = sorted(path for path in raw_dir.rglob("*.csv") if path.is_file())
    if not files:
        raise FileNotFoundError(f"N-BaIoT raw klasorunde CSV dosyasi bulunamadi: {raw_dir}")
    return files


def is_metadata_file(path: Path) -> bool:
    return path.name.lower() in METADATA_FILES


def infer_label_and_attack_type(path: Path) -> tuple[int, str]:
    name = path.name.lower()
    if "benign" in name:
        return 0, "benign"
    if "mirai" in name:
        return 1, "mirai"
    if "gafgyt" in name:
        return 1, "gafgyt"
    if "bashlite" in name:
        return 1, "bashlite"
    return 1, "attack_unknown"


def infer_source_device(path: Path, raw_dir: Path) -> str:
    parent = path.parent
    if parent.resolve() != raw_dir.resolve():
        return parent.name

    match = re.match(r"^(\d+)[._-]", path.name)
    if match:
        return f"device_{match.group(1)}"
    return "device_unknown"


def drop_index_like_columns(df: pd.DataFrame) -> pd.DataFrame:
    keep_columns = [
        column
        for column in df.columns
        if not str(column).lower().startswith("unnamed")
        and str(column).strip().lower() not in {"index", ""}
    ]
    return df[keep_columns]


def load_processed_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Processed N-BaIoT dataset bulunamadi: {path}. "
            "Once evaluation/preprocess_nbaiot.py calistirin."
        )

    df = pd.read_csv(path)
    missing = [column for column in TARGET_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"Processed dataset eksik kolonlara sahip: {', '.join(sorted(missing))}")

    if df.empty:
        raise ValueError("Processed dataset bos. not enough data.")

    feature_columns = [
        column
        for column in df.columns
        if column not in TARGET_COLUMNS and pd.api.types.is_numeric_dtype(df[column])
    ]
    if not feature_columns:
        raise ValueError("Egitim icin numeric feature kolonu bulunamadi.")

    y = pd.to_numeric(df["label"], errors="coerce")
    if y.isna().any():
        raise ValueError("label kolonunda sayisal olmayan deger var.")
    y = y.astype(int)

    labels = set(y.unique())
    if labels - {0, 1}:
        raise ValueError(f"label sadece 0 veya 1 olabilir. Gecersiz degerler: {sorted(labels - {0, 1})}")
    if y.nunique() < 2:
        raise ValueError("Egitim icin hem benign hem attack sinifi gerekir. not enough data.")

    x = df[feature_columns].replace([np.inf, -np.inf], np.nan)
    if x.isna().any().any():
        bad_columns = x.columns[x.isna().any()].tolist()
        raise ValueError(f"Feature kolonlarinda NaN/inf var: {', '.join(bad_columns[:10])}")

    return x.astype(np.float32), y, feature_columns


def get_feature_columns_from_csv(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Dataset bulunamadi: {path}")
    header = pd.read_csv(path, nrows=0)
    missing = [column for column in TARGET_COLUMNS if column not in header.columns]
    if missing:
        raise ValueError(f"Dataset eksik kolonlara sahip: {', '.join(sorted(missing))}")
    return [column for column in header.columns if column not in TARGET_COLUMNS]


def capped_sample(
    df: pd.DataFrame,
    max_rows: int | None,
    random_state: int,
) -> pd.DataFrame:
    if max_rows is None or max_rows <= 0 or len(df) <= max_rows:
        return df
    return df.sample(n=max_rows, random_state=random_state)


def load_filtered_sample(
    path: Path,
    predicate,
    max_rows: int | None,
    random_state: int = 42,
    chunksize: int = 100000,
) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Dataset bulunamadi: {path}")

    sample = []
    state = random_state
    for chunk in pd.read_csv(path, chunksize=chunksize):
        filtered = predicate(chunk)
        if filtered.empty:
            continue
        sample.append(filtered)
        combined = pd.concat(sample, ignore_index=True)
        if max_rows is not None and max_rows > 0 and len(combined) > max_rows:
            combined = combined.sample(n=max_rows, random_state=state)
            state += 1
        sample = [combined.reset_index(drop=True)]

    if not sample:
        return pd.DataFrame()
    return sample[0].reset_index(drop=True)


def clean_training_frame(df: pd.DataFrame, feature_columns: list[str]) -> tuple[pd.DataFrame, pd.Series]:
    if df.empty:
        raise ValueError("Egitim/test dataseti bos. not enough data.")
    missing = [column for column in [*feature_columns, "label"] if column not in df.columns]
    if missing:
        raise ValueError(f"Dataset eksik kolonlara sahip: {', '.join(missing[:20])}")
    x = df[feature_columns].apply(pd.to_numeric, errors="coerce")
    x = x.replace([np.inf, -np.inf], np.nan)
    valid_mask = ~x.isna().any(axis=1)
    x = x.loc[valid_mask].astype(np.float32)
    y = pd.to_numeric(df.loc[valid_mask, "label"], errors="coerce").astype(int)
    if y.nunique() < 2:
        raise ValueError("Train/test icin hem benign hem anomaly sinifi gerekir. not enough data.")
    return x, y


def calculate_binary_metrics(y_true: Iterable[int], y_pred: Iterable[int]) -> dict:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "false_positive_rate": round(float(fpr), 6),
        "false_negative_rate": round(float(fnr), 6),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def write_classification_report(y_true, y_pred, output_path: Path) -> None:
    report = classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Anomaly"],
        output_dict=True,
        zero_division=0,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(report).transpose().to_csv(output_path)


def write_confusion_matrix_png(y_true, y_pred, output_path: Path, title: str) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(6, 5))
    image = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.figure.colorbar(image, ax=ax)
    ax.set_title(title)
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_xticks([0, 1], labels=["Normal", "Anomaly"])
    ax.set_yticks([0, 1], labels=["Normal", "Anomaly"])

    threshold = cm.max() / 2 if cm.size else 0
    for row in range(cm.shape[0]):
        for col in range(cm.shape[1]):
            ax.text(
                col,
                row,
                int(cm[row, col]),
                ha="center",
                va="center",
                color="white" if cm[row, col] > threshold else "black",
                fontsize=12,
                fontweight="bold",
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def summary_record(model_name: str, summary: dict) -> dict:
    metrics = summary.get("metrics", summary)
    return {
        "model": model_name,
        "experiment": summary.get("experiment", "standard"),
        "accuracy": metrics.get("accuracy"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "f1_score": metrics.get("f1_score"),
        "false_positive_rate": metrics.get("false_positive_rate"),
        "false_negative_rate": metrics.get("false_negative_rate"),
    }
