"""Train balanced N-BaIoT benchmark models."""

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
    clean_training_frame,
    ensure_nbaiot_dirs,
    get_feature_columns_from_csv,
    load_filtered_sample,
    write_classification_report,
    write_confusion_matrix_png,
    write_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT balanced benchmark egitimi.")
    parser.add_argument("--input", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--model", choices=["random_forest", "extra_trees", "hist_gradient_boosting"], default="random_forest")
    parser.add_argument("--samples-per-class", type=int, default=None)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def count_labels(path: Path) -> dict[int, int]:
    counts = {0: 0, 1: 0}
    for chunk in pd.read_csv(path, usecols=["label"], chunksize=200000):
        value_counts = chunk["label"].value_counts()
        counts[0] += int(value_counts.get(0, 0))
        counts[1] += int(value_counts.get(1, 0))
    return counts


def count_attacks(path: Path) -> dict[str, int]:
    counts = {}
    for chunk in pd.read_csv(path, usecols=["label", "attack_type"], chunksize=200000):
        attacks = chunk[chunk["label"] == 1]["attack_type"].value_counts()
        for attack, count in attacks.items():
            counts[str(attack)] = counts.get(str(attack), 0) + int(count)
    return counts


def build_model(model_name: str, random_state: int):
    if model_name == "random_forest":
        return RandomForestClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=random_state)
    if model_name == "extra_trees":
        return ExtraTreesClassifier(n_estimators=200, class_weight="balanced", n_jobs=-1, random_state=random_state)
    return HistGradientBoostingClassifier(random_state=random_state)


def load_balanced_dataset(path: Path, samples_per_class: int, random_state: int) -> pd.DataFrame:
    normal = load_filtered_sample(path, lambda df: df[df["label"] == 0], samples_per_class, random_state)
    attack_counts = count_attacks(path)
    families = sorted(attack_counts)
    if not families:
        raise ValueError("Balanced benchmark icin attack family bulunamadi.")
    per_family = max(1, samples_per_class // len(families))
    remainder = samples_per_class - (per_family * len(families))
    attack_frames = []
    warnings = []
    for index, family in enumerate(families):
        target = per_family + (1 if index < remainder else 0)
        frame = load_filtered_sample(
            path,
            lambda df, family=family: df[(df["label"] == 1) & (df["attack_type"] == family)],
            target,
            random_state + 100 + index,
        )
        if len(frame) < target:
            warnings.append(f"{family}: requested={target}, available_sampled={len(frame)}")
        attack_frames.append(frame)
    attacks = pd.concat(attack_frames, ignore_index=True)
    if len(attacks) > samples_per_class:
        attacks = attacks.sample(n=samples_per_class, random_state=random_state + 999)
    if normal.empty or attacks.empty:
        raise ValueError("Balanced dataset icin normal veya attack ornegi yetersiz.")
    dataset = pd.concat([normal, attacks], ignore_index=True)
    dataset.attrs["sampling_warnings"] = warnings
    dataset.attrs["attack_family_counts"] = attacks["attack_type"].value_counts().to_dict()
    return dataset.sample(frac=1.0, random_state=random_state).reset_index(drop=True)


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        feature_columns = get_feature_columns_from_csv(args.input)
        label_counts = count_labels(args.input)
        samples_per_class = args.samples_per_class or min(label_counts.values())
        if samples_per_class < 2:
            raise ValueError("Balanced benchmark icin sinif basina en az 2 ornek gerekir.")

        dataset = load_balanced_dataset(args.input, samples_per_class, args.random_state)
        x, y = clean_training_frame(dataset, feature_columns)
        x_train, x_test, y_train, y_test = train_test_split(
            x,
            y,
            test_size=args.test_size,
            stratify=y,
            random_state=args.random_state,
        )

        model = build_model(args.model, args.random_state)
        print(f"[INFO] Balanced {args.model} egitiliyor: train={len(x_train)}, test={len(x_test)}")
        model.fit(x_train, y_train)
        y_pred = model.predict(x_test)
        metrics = calculate_binary_metrics(y_test, y_pred)
        prefix = f"nbaiot_balanced_{args.model}"
        summary_path = RESULTS_DIR / f"{prefix}_summary.json"
        report_path = RESULTS_DIR / f"{prefix}_classification_report.csv"
        matrix_path = RESULTS_DIR / f"{prefix}_confusion_matrix.png"
        model_path = MODELS_DIR / f"{prefix}.pkl"
        summary = {
            "experiment": "balanced_random_split",
            "model": f"balanced_{args.model}",
            "input": str(args.input),
            "samples_per_class": samples_per_class,
            "sample_count": int(len(x)),
            "train_count": int(len(x_train)),
            "test_count": int(len(x_test)),
            "feature_count": len(feature_columns),
            "attack_family_counts": dataset.attrs.get("attack_family_counts", {}),
            "sampling_warnings": dataset.attrs.get("sampling_warnings", []),
            "metrics": metrics,
        }
        write_json(summary_path, summary)
        write_classification_report(y_test, y_pred, report_path)
        write_confusion_matrix_png(y_test, y_pred, matrix_path, "N-BaIoT Balanced Benchmark Confusion Matrix")
        joblib.dump({"model": model, "feature_columns": feature_columns, "summary": summary}, model_path)
        if hasattr(model, "feature_importances_"):
            importance_path = RESULTS_DIR / f"{prefix}_feature_importance.csv"
            pd.DataFrame({"feature": feature_columns, "importance": model.feature_importances_}).sort_values(
                "importance", ascending=False
            ).to_csv(importance_path, index=False)
            print(f"[OK] Feature importance: {importance_path}")
    except Exception as exc:
        print(f"[HATA] Balanced benchmark basarisiz: {exc}")
        return 1

    print(f"[OK] Balanced summary: {summary_path}")
    print(f"[OK] F1-score: {metrics['f1_score']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
