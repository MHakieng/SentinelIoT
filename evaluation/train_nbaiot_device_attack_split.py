"""Evaluate N-BaIoT model on unseen devices and unseen attack families."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

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
    parser = argparse.ArgumentParser(description="N-BaIoT device + attack-family split benchmark.")
    parser.add_argument("--input", type=Path, default=DEFAULT_PROCESSED_DATASET)
    parser.add_argument("--max-train-normal", type=int, default=100000)
    parser.add_argument("--max-test-normal", type=int, default=50000)
    parser.add_argument("--max-train-attack", type=int, default=150000)
    parser.add_argument("--max-test-attack", type=int, default=150000)
    parser.add_argument("--test-device-size", type=float, default=0.3)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def load_devices_and_attacks(path: Path) -> tuple[list[str], list[str]]:
    devices = set()
    attacks = set()
    for chunk in pd.read_csv(path, usecols=["source_device", "attack_type", "label"], chunksize=200000):
        devices.update(chunk["source_device"].dropna().astype(str).unique())
        attacks.update(chunk.loc[chunk["label"] == 1, "attack_type"].dropna().astype(str).unique())
    attacks.discard("benign")
    if len(devices) < 2:
        raise ValueError("Device + attack split icin en az 2 source_device gerekir.")
    if len(attacks) < 2:
        raise ValueError("Device + attack split icin en az 2 attack_type gerekir.")
    return sorted(devices), sorted(attacks)


def build_model(random_state: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        n_jobs=-1,
        random_state=random_state,
    )


def main() -> int:
    args = build_parser().parse_args()
    try:
        ensure_nbaiot_dirs()
        feature_columns = get_feature_columns_from_csv(args.input)
        devices, attacks = load_devices_and_attacks(args.input)
        train_devices, test_devices = train_test_split(
            devices,
            test_size=args.test_device_size,
            random_state=args.random_state,
        )

        rows = []
        for index, held_out_attack in enumerate(attacks, start=1):
            train_attacks = [attack for attack in attacks if attack != held_out_attack]
            train_normal = load_filtered_sample(
                args.input,
                lambda df, train_devices=train_devices: (df[(df["label"] == 0) & (df["source_device"].isin(train_devices))]),
                args.max_train_normal,
                args.random_state + index,
            )
            test_normal = load_filtered_sample(
                args.input,
                lambda df, test_devices=test_devices: (df[(df["label"] == 0) & (df["source_device"].isin(test_devices))]),
                args.max_test_normal,
                args.random_state + 100 + index,
            )
            train_attack = load_filtered_sample(
                args.input,
                lambda df, train_devices=train_devices, train_attacks=train_attacks: df[
                    (df["label"] == 1)
                    & (df["source_device"].isin(train_devices))
                    & (df["attack_type"].isin(train_attacks))
                ],
                args.max_train_attack,
                args.random_state + 200 + index,
            )
            test_attack = load_filtered_sample(
                args.input,
                lambda df, test_devices=test_devices, held_out_attack=held_out_attack: df[
                    (df["label"] == 1)
                    & (df["source_device"].isin(test_devices))
                    & (df["attack_type"] == held_out_attack)
                ],
                args.max_test_attack,
                args.random_state + 300 + index,
            )
            if train_normal.empty or test_normal.empty or train_attack.empty or test_attack.empty:
                raise ValueError(f"{held_out_attack} icin device+attack split verisi yetersiz.")

            train_df = pd.concat([train_normal, train_attack], ignore_index=True)
            test_df = pd.concat([test_normal, test_attack], ignore_index=True)
            x_train, y_train = clean_training_frame(train_df, feature_columns)
            x_test, y_test = clean_training_frame(test_df, feature_columns)

            model = build_model(args.random_state)
            print(f"[INFO] Held-out attack={held_out_attack}: train={len(x_train)}, test={len(x_test)}")
            model.fit(x_train, y_train)
            y_pred = model.predict(x_test)
            metrics = calculate_binary_metrics(y_test, y_pred)
            rows.append(
                {
                    "test_attack_family": held_out_attack,
                    "train_attack_families": "|".join(train_attacks),
                    "train_devices": "|".join(train_devices),
                    "test_devices": "|".join(test_devices),
                    "train_rows": int(len(x_train)),
                    "test_rows": int(len(x_test)),
                    **metrics,
                }
            )
            print(f"[OK] {held_out_attack}: f1={metrics['f1_score']}")

        results_df = pd.DataFrame(rows).sort_values("f1_score", ascending=False)
        csv_path = RESULTS_DIR / "nbaiot_device_attack_split_results.csv"
        json_path = RESULTS_DIR / "nbaiot_device_attack_split_summary.json"
        matrix_path = RESULTS_DIR / "nbaiot_device_attack_split_confusion_matrix.png"
        results_df.to_csv(csv_path, index=False)

        # Plot the worst-case split because it is the most conservative evidence.
        worst = results_df.sort_values("f1_score", ascending=True).iloc[0]
        worst_attack = str(worst["test_attack_family"])
        worst_test_normal = load_filtered_sample(
            args.input,
            lambda df, test_devices=test_devices: (df[(df["label"] == 0) & (df["source_device"].isin(test_devices))]),
            args.max_test_normal,
            args.random_state + 999,
        )
        worst_test_attack = load_filtered_sample(
            args.input,
            lambda df, test_devices=test_devices, worst_attack=worst_attack: df[
                (df["label"] == 1)
                & (df["source_device"].isin(test_devices))
                & (df["attack_type"] == worst_attack)
            ],
            args.max_test_attack,
            args.random_state + 1000,
        )
        # Reconstruct matrix from stored counts for deterministic output.
        cm = worst["confusion_matrix"]
        y_true = [0] * (cm["true_negative"] + cm["false_positive"]) + [1] * (cm["false_negative"] + cm["true_positive"])
        y_pred = [0] * cm["true_negative"] + [1] * cm["false_positive"] + [0] * cm["false_negative"] + [1] * cm["true_positive"]
        write_confusion_matrix_png(y_true, y_pred, matrix_path, "N-BaIoT Device + Attack Split Confusion Matrix")

        summary = {
            "experiment": "device_attack_split",
            "model": "device_attack_split_random_forest",
            "input": str(args.input),
            "train_devices": list(train_devices),
            "test_devices": list(test_devices),
            "attack_families": attacks,
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
            "worst_case_attack_family": worst_attack,
            "results": rows,
        }
        write_json(json_path, summary)
    except Exception as exc:
        print(f"[HATA] Device + attack split basarisiz: {exc}")
        return 1

    print(f"[OK] Device + attack split CSV: {csv_path}")
    print(f"[OK] Device + attack split summary: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
