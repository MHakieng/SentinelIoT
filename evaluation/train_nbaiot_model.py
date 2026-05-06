"""Train supervised N-BaIoT binary classification benchmark models."""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split

from nbaiot_utils import (
    DEFAULT_PROCESSED_DATASET,
    MODELS_DIR,
    RESULTS_DIR,
    calculate_binary_metrics,
    ensure_nbaiot_dirs,
    load_processed_dataset,
    write_classification_report,
    write_confusion_matrix_png,
    write_json,
)


SUPPORTED_MODELS = {"random_forest", "extra_trees", "hist_gradient_boosting"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT supervised model benchmark egitimi.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--model", choices=sorted(SUPPORTED_MODELS), default="random_forest")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def build_model(model_name: str, random_state: int):
    if model_name == "random_forest":
        return RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            n_jobs=-1,
            random_state=random_state,
        )
    if model_name == "extra_trees":
        return ExtraTreesClassifier(
            n_estimators=200,
            class_weight="balanced",
            n_jobs=-1,
            random_state=random_state,
        )
    if model_name == "hist_gradient_boosting":
        return HistGradientBoostingClassifier(random_state=random_state)
    raise ValueError(f"Desteklenmeyen model: {model_name}")


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        x, y, feature_columns = load_processed_dataset(args.dataset)
        x_train, x_test, y_train, y_test = train_test_split(
            x,
            y,
            test_size=args.test_size,
            stratify=y,
            random_state=args.random_state,
        )
        model = build_model(args.model, args.random_state)
        print(f"[INFO] {args.model} egitiliyor: train={len(x_train)}, test={len(x_test)}, features={len(feature_columns)}")
        model.fit(x_train, y_train)
        y_pred = model.predict(x_test)
        metrics = calculate_binary_metrics(y_test, y_pred)

        prefix = f"nbaiot_{args.model}"
        summary_path = RESULTS_DIR / f"{prefix}_summary.json"
        report_path = RESULTS_DIR / f"{prefix}_classification_report.csv"
        matrix_path = RESULTS_DIR / f"{prefix}_confusion_matrix.png"
        model_path = MODELS_DIR / f"{prefix}.pkl"

        summary = {
            "model": args.model,
            "dataset": str(args.dataset),
            "sample_count": int(len(x)),
            "train_count": int(len(x_train)),
            "test_count": int(len(x_test)),
            "test_size": args.test_size,
            "random_state": args.random_state,
            "feature_count": len(feature_columns),
            "metrics": metrics,
        }
        write_json(summary_path, summary)
        write_classification_report(y_test, y_pred, report_path)
        write_confusion_matrix_png(
            y_test,
            y_pred,
            matrix_path,
            "N-BaIoT Binary Classification Confusion Matrix",
        )
        joblib.dump({"model": model, "feature_columns": feature_columns, "summary": summary}, model_path)

        if hasattr(model, "feature_importances_"):
            importance_path = RESULTS_DIR / f"{prefix}_feature_importance.csv"
            importance = pd.DataFrame(
                {"feature": feature_columns, "importance": model.feature_importances_}
            ).sort_values("importance", ascending=False)
            importance.to_csv(importance_path, index=False)
            print(f"[OK] Feature importance: {importance_path}")
    except Exception as exc:
        print(f"[HATA] N-BaIoT model egitimi basarisiz: {exc}")
        return 1

    print(f"[OK] Model kaydedildi: {model_path}")
    print(f"[OK] Summary: {summary_path}")
    print(f"[OK] F1-score: {metrics['f1_score']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
