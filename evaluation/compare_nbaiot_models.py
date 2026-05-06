"""Compare N-BaIoT benchmark model results."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from nbaiot_utils import RESULTS_DIR, ensure_nbaiot_dirs, summary_record


def load_json_summaries() -> list[dict]:
    rows = []
    for path in sorted(RESULTS_DIR.glob("nbaiot_*_summary.json")):
        with path.open("r", encoding="utf-8") as handle:
            summary = json.load(handle)
        model_name = str(summary.get("model") or path.stem.replace("nbaiot_", "").replace("_summary", ""))
        rows.append(summary_record(model_name, summary))
    return rows


def load_split_summary(path: Path, model_name: str) -> dict | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        summary = json.load(handle)
    metrics = summary.get("mean_metrics") or summary.get("metrics") or {}
    return {
        "model": model_name,
        "experiment": summary.get("experiment", model_name),
        "accuracy": metrics.get("accuracy"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "f1_score": metrics.get("f1_score"),
        "false_positive_rate": metrics.get("false_positive_rate"),
        "false_negative_rate": metrics.get("false_negative_rate"),
    }


def load_isolation_forest_rows() -> list[dict]:
    path = RESULTS_DIR / "nbaiot_isolation_forest_tuning.csv"
    if not path.exists():
        return []
    df = pd.read_csv(path)
    rows = []
    for _, row in df.iterrows():
        rows.append(
            {
                "model": row.get("model", f"isolation_forest_{row.get('contamination')}"),
                "experiment": "isolation_forest_tuning",
                "accuracy": row.get("accuracy"),
                "precision": row.get("precision"),
                "recall": row.get("recall"),
                "f1_score": row.get("f1_score"),
                "false_positive_rate": row.get("false_positive_rate"),
                "false_negative_rate": row.get("false_negative_rate"),
            }
        )
    return rows


def load_generalization_rows(all_rows: list[dict]) -> list[dict]:
    wanted = {
        "random_forest": "Random Split RF",
        "random_forest_device_split": "Device Split RF",
        "attack_split_random_forest": "Attack Split RF",
        "device_attack_split_random_forest": "Device + Attack Split RF",
        "balanced_random_forest": "Balanced RF",
    }
    rows = []
    for row in all_rows:
        model = str(row.get("model"))
        if model in wanted:
            item = dict(row)
            item["model"] = wanted[model]
            rows.append(item)

    if_rows = [row for row in all_rows if str(row.get("model", "")).startswith("isolation_forest_")]
    if if_rows:
        best_if = max(if_rows, key=lambda row: float(row.get("f1_score") or 0))
        item = dict(best_if)
        item["model"] = "Isolation Forest"
        rows.append(item)
    return rows


def write_bar_chart(df: pd.DataFrame, output_path: Path, title: str = "N-BaIoT Model Comparison by F1-score") -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(df["model"], df["f1_score"])
    ax.set_title(title)
    ax.set_xlabel("Model")
    ax.set_ylabel("F1-score")
    ax.set_ylim(0, 1)
    ax.tick_params(axis="x", rotation=35)
    fig.tight_layout()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def main() -> int:
    try:
        ensure_nbaiot_dirs()
        rows = load_json_summaries() + load_isolation_forest_rows()
        extra_summaries = [
            load_split_summary(RESULTS_DIR / "nbaiot_attack_split_summary.json", "attack_split_random_forest"),
            load_split_summary(RESULTS_DIR / "nbaiot_device_attack_split_summary.json", "device_attack_split_random_forest"),
        ]
        rows.extend([row for row in extra_summaries if row])
        if not rows:
            raise FileNotFoundError("Karsilastirma icin nbaiot summary/tuning sonucu bulunamadi.")
        df = pd.DataFrame(rows)
        df = df.dropna(subset=["f1_score"]).sort_values("f1_score", ascending=False)
        csv_path = RESULTS_DIR / "nbaiot_model_comparison.csv"
        png_path = RESULTS_DIR / "nbaiot_model_comparison.png"
        df.to_csv(csv_path, index=False)
        write_bar_chart(df, png_path)

        generalization = pd.DataFrame(load_generalization_rows(df.to_dict("records")))
        gen_csv_path = RESULTS_DIR / "nbaiot_generalization_comparison.csv"
        gen_png_path = RESULTS_DIR / "nbaiot_generalization_comparison.png"
        if not generalization.empty:
            generalization = generalization.dropna(subset=["f1_score"]).sort_values("f1_score", ascending=False)
            generalization.to_csv(gen_csv_path, index=False)
            write_bar_chart(generalization, gen_png_path, "N-BaIoT Generalization Tests by F1-score")
    except Exception as exc:
        print(f"[HATA] Model karsilastirma basarisiz: {exc}")
        return 1

    print(f"[OK] Karsilastirma CSV: {csv_path}")
    print(f"[OK] Karsilastirma PNG: {png_path}")
    if 'gen_csv_path' in locals() and gen_csv_path.exists():
        print(f"[OK] Generalization CSV: {gen_csv_path}")
        print(f"[OK] Generalization PNG: {gen_png_path}")
    print(df[["model", "f1_score"]].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
