"""Analyze N-BaIoT feature importance and possible leakage-like separation."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from nbaiot_utils import (
    DEFAULT_PROCESSED_DATASET,
    RESULTS_DIR,
    ensure_nbaiot_dirs,
    get_feature_columns_from_csv,
    load_filtered_sample,
)


DEFAULT_IMPORTANCE = RESULTS_DIR / "nbaiot_random_forest_feature_importance.csv"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT feature leakage / importance analizi.")
    parser.add_argument("--input", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--importance", type=Path, default=DEFAULT_IMPORTANCE)
    parser.add_argument("--sample-size", type=int, default=200000)
    parser.add_argument("--top-n", type=int, default=30)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def load_balanced_sample(path: Path, sample_size: int, random_state: int) -> pd.DataFrame:
    per_class = max(2, sample_size // 2)
    normal = load_filtered_sample(path, lambda df: df[df["label"] == 0], per_class, random_state)
    anomaly = load_filtered_sample(path, lambda df: df[df["label"] == 1], per_class, random_state + 1)
    if normal.empty or anomaly.empty:
        raise ValueError("Leakage analizi icin normal/anomaly ornegi yetersiz.")
    return pd.concat([normal, anomaly], ignore_index=True).sample(frac=1.0, random_state=random_state)


def load_or_build_importance(path: Path, df: pd.DataFrame, feature_columns: list[str], random_state: int) -> pd.DataFrame:
    if path.exists():
        importance = pd.read_csv(path)
        if {"feature", "importance"}.issubset(importance.columns):
            return importance.sort_values("importance", ascending=False)

    x = df[feature_columns].apply(pd.to_numeric, errors="coerce").fillna(0).astype(np.float32)
    y = df["label"].astype(int)
    model = RandomForestClassifier(
        n_estimators=80,
        class_weight="balanced",
        n_jobs=-1,
        random_state=random_state,
    )
    model.fit(x, y)
    return pd.DataFrame({"feature": feature_columns, "importance": model.feature_importances_}).sort_values(
        "importance", ascending=False
    )


def effect_size(normal: pd.Series, anomaly: pd.Series) -> float:
    normal_mean = float(normal.mean())
    anomaly_mean = float(anomaly.mean())
    pooled = float(np.sqrt((normal.var(ddof=0) + anomaly.var(ddof=0)) / 2))
    if pooled == 0:
        return 0.0 if normal_mean == anomaly_mean else 999.0
    return abs(anomaly_mean - normal_mean) / pooled


def single_feature_f1(df: pd.DataFrame, feature: str, random_state: int) -> float:
    x = pd.to_numeric(df[feature], errors="coerce").fillna(0).to_frame().astype(np.float32)
    y = df["label"].astype(int)
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.25,
        stratify=y,
        random_state=random_state,
    )
    model = DecisionTreeClassifier(max_depth=1, random_state=random_state)
    model.fit(x_train, y_train)
    return round(float(f1_score(y_test, model.predict(x_test), zero_division=0)), 6)


def write_importance_chart(df: pd.DataFrame, output_path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    chart_df = df.head(20).iloc[::-1]
    fig, ax = plt.subplots(figsize=(9, 7))
    ax.barh(chart_df["feature"], chart_df["importance"])
    ax.set_title("N-BaIoT Top Feature Importance")
    ax.set_xlabel("Importance")
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        feature_columns = get_feature_columns_from_csv(args.input)
        sample = load_balanced_sample(args.input, args.sample_size, args.random_state)
        importance = load_or_build_importance(args.importance, sample, feature_columns, args.random_state)
        top_features = [feature for feature in importance["feature"].head(args.top_n).tolist() if feature in sample.columns]
        if not top_features:
            raise ValueError("Analiz icin top feature bulunamadi.")

        rows = []
        score_rows = []
        for feature in top_features:
            values = pd.to_numeric(sample[feature], errors="coerce").fillna(0)
            normal = values[sample["label"] == 0]
            anomaly = values[sample["label"] == 1]
            f1 = single_feature_f1(sample, feature, args.random_state)
            separation = round(float(effect_size(normal, anomaly)), 6)
            leakage_suspect = bool(f1 >= 0.95)
            suspicious = bool(separation >= 5.0)
            row = {
                "feature": feature,
                "importance": float(importance.loc[importance["feature"] == feature, "importance"].iloc[0]),
                "normal_mean": round(float(normal.mean()), 6),
                "anomaly_mean": round(float(anomaly.mean()), 6),
                "normal_std": round(float(normal.std(ddof=0)), 6),
                "anomaly_std": round(float(anomaly.std(ddof=0)), 6),
                "effect_size": separation,
                "single_feature_f1": f1,
                "leakage_suspect": leakage_suspect,
                "suspicious": suspicious,
            }
            rows.append(row)
            score_rows.append({"feature": feature, "single_feature_f1": f1})

        analysis_path = RESULTS_DIR / "nbaiot_feature_leakage_analysis.csv"
        scores_path = RESULTS_DIR / "nbaiot_single_feature_scores.csv"
        chart_path = RESULTS_DIR / "nbaiot_top_feature_importance.png"
        pd.DataFrame(rows).sort_values("single_feature_f1", ascending=False).to_csv(analysis_path, index=False)
        pd.DataFrame(score_rows).sort_values("single_feature_f1", ascending=False).to_csv(scores_path, index=False)
        write_importance_chart(importance, chart_path)
    except Exception as exc:
        print(f"[HATA] Feature leakage analizi basarisiz: {exc}")
        return 1

    print(f"[OK] Leakage analysis: {analysis_path}")
    print(f"[OK] Single feature scores: {scores_path}")
    print(f"[OK] Top feature chart: {chart_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
