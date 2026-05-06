"""Validate SentinelIoT anomaly detection on labelled flow feature CSV data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = PROJECT_ROOT / "evaluation" / "flow_validation_dataset.csv"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "avg_packet_size",
    "mean_iat",
    "var_iat",
]
REQUIRED_COLUMNS = [*FEATURE_COLUMNS, "label", "attack_type"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelIoT anomaly model dogrulama scripti.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help=f"Dogrulama CSV yolu. Varsayilan: {DEFAULT_DATASET}",
    )
    return parser


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset bulunamadi: {path}. Once evaluation/export_flow_dataset.py calistirin "
            "veya evaluation/flow_validation_dataset.example.csv formatina gore veri girin."
        )

    df = pd.read_csv(path)
    missing = [column for column in REQUIRED_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"Dataset eksik kolonlara sahip: {', '.join(missing)}")

    if df.empty:
        raise ValueError("Dataset bos. not enough data.")

    invalid_labels = sorted(set(df["label"].dropna().astype(int)) - {0, 1})
    if invalid_labels:
        raise ValueError(f"label sadece 0 veya 1 olabilir. Gecersiz degerler: {invalid_labels}")

    numeric = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    if numeric.isna().any().any():
        bad_columns = numeric.columns[numeric.isna().any()].tolist()
        raise ValueError(f"Feature kolonlarinda eksik/bozuk sayisal veri var: {', '.join(bad_columns)}")

    if not np.isfinite(numeric.to_numpy(dtype=float)).all():
        raise ValueError("Feature kolonlarinda sonsuz veya gecersiz sayisal deger var.")

    df[FEATURE_COLUMNS] = numeric.astype(float)
    df["label"] = df["label"].astype(int)
    df["attack_type"] = df["attack_type"].fillna("unknown").astype(str)
    return df


def validate_data_volume(df: pd.DataFrame) -> None:
    normal_count = int((df["label"] == 0).sum())
    anomaly_count = int((df["label"] == 1).sum())
    if normal_count < 2:
        raise ValueError("Normal trafik train seti icin not enough data: en az 2 normal kayit gerekir.")
    if anomaly_count < 1:
        raise ValueError("Anomali metrikleri icin not enough data: en az 1 anomaly kaydi gerekir.")


def train_and_predict(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    train_df = df[df["label"] == 0]
    scaler = StandardScaler()
    x_train = scaler.fit_transform(train_df[FEATURE_COLUMNS])
    x_all = scaler.transform(df[FEATURE_COLUMNS])

    model = IsolationForest(random_state=42)
    model.fit(x_train)

    raw_pred = model.predict(x_all)
    y_pred = np.where(raw_pred == -1, 1, 0)
    y_true = df["label"].to_numpy(dtype=int)
    return y_true, y_pred


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
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


def write_classification_report(y_true: np.ndarray, y_pred: np.ndarray, output_path: Path) -> None:
    report = classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Anomaly"],
        output_dict=True,
        zero_division=0,
    )
    pd.DataFrame(report).transpose().to_csv(output_path)


def write_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, output_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(6, 5))
    image = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.figure.colorbar(image, ax=ax)
    ax.set_title("Anomaly Detection Confusion Matrix")
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

    fig.tight_layout()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def main() -> int:
    args = build_parser().parse_args()
    try:
        df = load_dataset(args.dataset)
        validate_data_volume(df)
        y_true, y_pred = train_and_predict(df)
        metrics = calculate_metrics(y_true, y_pred)

        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        summary_path = RESULTS_DIR / "evaluation_summary.json"
        report_path = RESULTS_DIR / "classification_report.csv"
        matrix_path = RESULTS_DIR / "confusion_matrix.png"

        summary = {
            "dataset": str(args.dataset),
            "sample_count": int(len(df)),
            "normal_count": int((df["label"] == 0).sum()),
            "anomaly_count": int((df["label"] == 1).sum()),
            "features": FEATURE_COLUMNS,
            "model": "IsolationForest(random_state=42)",
            "scaler": "StandardScaler",
            "metrics": metrics,
        }

        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        write_classification_report(y_true, y_pred, report_path)
        write_confusion_matrix(y_true, y_pred, matrix_path)
    except Exception as exc:
        print(f"[HATA] Anomaly model dogrulamasi basarisiz: {exc}")
        return 1

    print("[OK] Anomaly model dogrulamasi tamamlandi.")
    print(f"  JSON: {summary_path}")
    print(f"  CSV : {report_path}")
    print(f"  PNG : {matrix_path}")
    print(f"  F1  : {metrics['f1_score']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
