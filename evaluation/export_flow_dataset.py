"""Export existing SentinelIoT flow feature data into evaluation CSV format."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = PROJECT_ROOT / "sentinel_iot" / "iot_traffic_dataset.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "evaluation" / "flow_validation_dataset.csv"

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "avg_packet_size",
    "mean_iat",
    "var_iat",
]
OUTPUT_COLUMNS = [*FEATURE_COLUMNS, "label", "attack_type"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SentinelIoT flow feature CSV dosyasini evaluation formatina aktarir."
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help=f"Kaynak CSV yolu. Varsayilan: {DEFAULT_SOURCE}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Cikti CSV yolu. Varsayilan: {DEFAULT_OUTPUT}",
    )
    return parser


def validate_source(df: pd.DataFrame, source: Path) -> None:
    missing = [column for column in [*FEATURE_COLUMNS, "label"] if column not in df.columns]
    if missing:
        raise ValueError(f"{source} eksik kolonlara sahip: {', '.join(missing)}")


def normalize_attack_type(row: pd.Series) -> str:
    if "attack_type" in row and pd.notna(row["attack_type"]) and str(row["attack_type"]).strip():
        return str(row["attack_type"]).strip()
    if int(row["label"]) == 0:
        return "normal"
    return "unlabeled_anomaly"


def export_dataset(source: Path, output: Path) -> int:
    if not source.exists():
        raise FileNotFoundError(
            f"Kaynak flow verisi bulunamadi: {source}. "
            "Gercek verileri evaluation/flow_validation_dataset.csv dosyasina manuel ekleyin "
            "veya evaluation/flow_validation_dataset.example.csv formatini kullanin."
        )

    df = pd.read_csv(source)
    validate_source(df, source)

    exported = df[[*FEATURE_COLUMNS, "label"]].copy()
    exported["attack_type"] = df.apply(normalize_attack_type, axis=1)
    exported = exported[OUTPUT_COLUMNS]

    output.parent.mkdir(parents=True, exist_ok=True)
    exported.to_csv(output, index=False)
    return len(exported)


def main() -> int:
    args = build_parser().parse_args()
    try:
        row_count = export_dataset(args.source, args.output)
    except Exception as exc:
        print(f"[HATA] Flow dataset export basarisiz: {exc}")
        return 1

    print(f"[OK] {row_count} flow kaydi aktarildi: {args.output}")
    print("[NOT] attack_type kaynakta yoksa anomaly kayitlari 'unlabeled_anomaly' olarak isaretlenir.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
