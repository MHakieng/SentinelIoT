"""Check or run N-BaIoT trained model against live Sentinel-IoT flow snapshots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = PROJECT_ROOT / "evaluation" / "models" / "nbaiot_random_forest.pkl"
DEFAULT_INPUT = PROJECT_ROOT / "evaluation" / "live" / "live_flow_snapshots.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "evaluation" / "results" / "live_nbaiot_shadow_predictions.csv"
DEFAULT_REPORT = PROJECT_ROOT / "evaluation" / "results" / "live_nbaiot_shadow_check.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="N-BaIoT modelinin canli Sentinel flow featurelariyla uyumlulugunu kontrol eder.")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser


def write_report(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    args = build_parser().parse_args()
    try:
        if not args.model.exists():
            raise FileNotFoundError(f"Model bulunamadi: {args.model}")
        if not args.input.exists():
            raise FileNotFoundError(f"Canli flow CSV bulunamadi: {args.input}")

        package = joblib.load(args.model)
        model = package.get("model") if isinstance(package, dict) else package
        feature_columns = package.get("feature_columns") if isinstance(package, dict) else None
        if not feature_columns:
            raise ValueError("Model paketinde feature_columns bilgisi yok.")

        df = pd.read_csv(args.input)
        available_columns = set(df.columns)
        missing = [column for column in feature_columns if column not in available_columns]
        report = {
            "model": str(args.model),
            "input": str(args.input),
            "compatible": not missing,
            "expected_feature_count": len(feature_columns),
            "available_column_count": len(df.columns),
            "missing_feature_count": len(missing),
            "missing_features_sample": missing[:25],
            "message": "",
        }

        if missing:
            report["message"] = (
                "N-BaIoT supervised modeli canli Sentinel-IoT flow snapshotlariyla dogrudan uyumlu degil. "
                "N-BaIoT modelinde 115 civari istatistiksel feature beklenir; canli sistemde flow extractor "
                "packet_count, byte_count, duration, avg_packet_size, mean_iat, var_iat gibi daha kisa bir sema uretir."
            )
            write_report(args.report, report)
            print(f"[UYARI] Model-feature uyumsuzlugu raporlandi: {args.report}")
            print(report["message"])
            return 0

        x = df[feature_columns]
        predictions = model.predict(x)
        output = df.copy()
        output["nbaiot_shadow_prediction"] = predictions
        args.output.parent.mkdir(parents=True, exist_ok=True)
        output.to_csv(args.output, index=False)
        report["message"] = "N-BaIoT modeli canli snapshot uzerinde shadow mode tahmin uretti."
        report["prediction_counts"] = pd.Series(predictions).value_counts().sort_index().to_dict()
        write_report(args.report, report)
    except Exception as exc:
        print(f"[HATA] Shadow prediction basarisiz: {exc}")
        return 1

    print(f"[OK] Shadow prediction CSV: {args.output}")
    print(f"[OK] Rapor: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
