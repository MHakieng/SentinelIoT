"""Evaluate generalization to held-out N-BaIoT attack families."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from nbaiot_utils import (
    DEFAULT_PROCESSED_DATASET,
    RESULTS_DIR,
    calculate_binary_metrics,
    clean_training_frame,
    ensure_nbaiot_dirs,
    get_feature_columns_from_csv,
    load_filtered_sample,
    write_confusion_matrix_png,
    write_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT attack-family split benchmark.")
    parser.add_argument("--input", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--model", choices=["random_forest"], default="random_forest")
    parser.add_argument("--max-train-normal", type=int, default=100000)
    parser.add_argument("--max-test-normal", type=int, default=50000)
    parser.add_argument("--max-train-attack", type=int, default=150000)
    parser.add_argument("--max-test-attack", type=int, default=150000)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def build_model(random_state: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        n_jobs=-1,
        random_state=random_state,
    )


def load_attack_families(path: Path) -> list[str]:
    families = set()
    for chunk in pd.read_csv(path, usecols=["label", "attack_type"], chunksize=200000):
        attacks = chunk.loc[chunk["label"] == 1, "attack_type"].dropna().astype(str)
        families.update(attacks.unique())
    families.discard("benign")
    if len(families) < 2:
        raise ValueError("Attack-family split icin en az 2 attack_type gerekir.")
    return sorted(families)


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        feature_columns = get_feature_columns_from_csv(args.input)
        families = load_attack_families(args.input)
        normal_train = load_filtered_sample(
            args.input,
            lambda df: df[df["label"] == 0],
            args.max_train_normal,
            args.random_state,
        )
        normal_test = load_filtered_sample(
            args.input,
            lambda df: df[df["label"] == 0],
            args.max_test_normal,
            args.random_state + 101,
        )
        if normal_train.empty or normal_test.empty:
            raise ValueError("Benign train/test ornegi bulunamadi.")

        rows = []
        for index, held_out in enumerate(families, start=1):
            train_attacks = [family for family in families if family != held_out]
            train_attack_df = load_filtered_sample(
                args.input,
                lambda df, train_attacks=train_attacks: df[(df["label"] == 1) & (df["attack_type"].isin(train_attacks))],
                args.max_train_attack,
                args.random_state + index,
            )
            test_attack_df = load_filtered_sample(
                args.input,
                lambda df, held_out=held_out: df[(df["label"] == 1) & (df["attack_type"] == held_out)],
                args.max_test_attack,
                args.random_state + 1000 + index,
            )
            if train_attack_df.empty or test_attack_df.empty:
                raise ValueError(f"{held_out} icin train/test attack ornegi yetersiz.")

            train_df = pd.concat([normal_train, train_attack_df], ignore_index=True)
            test_df = pd.concat([normal_test, test_attack_df], ignore_index=True)
            x_train, y_train = clean_training_frame(train_df, feature_columns)
            x_test, y_test = clean_training_frame(test_df, feature_columns)

            model = build_model(args.random_state)
            print(f"[INFO] Held-out attack={held_out}: train={len(x_train)}, test={len(x_test)}")
            model.fit(x_train, y_train)
            y_pred = model.predict(x_test)
            metrics = calculate_binary_metrics(y_test, y_pred)
            matrix_path = RESULTS_DIR / f"nbaiot_attack_split_confusion_matrix_{held_out}.png"
            write_confusion_matrix_png(
                y_test,
                y_pred,
                matrix_path,
                "N-BaIoT Attack-Family Split Confusion Matrix",
            )

            rows.append(
                {
                    "test_attack_family": held_out,
                    "train_attack_families": "|".join(train_attacks),
                    "train_rows": int(len(x_train)),
                    "test_rows": int(len(x_test)),
                    **metrics,
                }
            )
            print(f"[OK] {held_out}: f1={metrics['f1_score']}")

        results_df = pd.DataFrame(rows).sort_values("f1_score", ascending=False)
        csv_path = RESULTS_DIR / "nbaiot_attack_split_results.csv"
        json_path = RESULTS_DIR / "nbaiot_attack_split_summary.json"
        results_df.to_csv(csv_path, index=False)
        summary = {
            "experiment": "attack_family_split",
            "model": "attack_split_random_forest",
            "input": str(args.input),
            "attack_families": families,
            "sampling": {
                "max_train_normal": args.max_train_normal,
                "max_test_normal": args.max_test_normal,
                "max_train_attack": args.max_train_attack,
                "max_test_attack": args.max_test_attack,
            },
            "mean_metrics": results_df[
                ["accuracy", "precision", "recall", "f1_score", "false_positive_rate", "false_negative_rate"]
            ].mean(numeric_only=True).round(6).to_dict(),
            "worst_f1_score": float(results_df["f1_score"].min()),
            "best_f1_score": float(results_df["f1_score"].max()),
            "results": rows,
        }
        write_json(json_path, summary)
    except Exception as exc:
        print(f"[HATA] Attack-family split basarisiz: {exc}")
        return 1

    print(f"[OK] Attack split CSV: {csv_path}")
    print(f"[OK] Attack split summary: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
