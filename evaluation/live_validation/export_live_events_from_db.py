"""Export live anomaly events from Sentinel-IoT SQLite DB.

The output format is compatible with
`evaluation/live_validation/evaluate_live_detection.py`.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "sentinel_iot" / "sentinel_iot.db"
DEFAULT_OUTPUT = PROJECT_ROOT / "evaluation" / "live_validation" / "live_events.csv"
OUTPUT_COLUMNS = ["timestamp", "device_ip", "attack_probability", "is_anomaly"]
REQUIRED_COLUMNS = {"timestamp", "device_ip", "score", "details"}


def parse_iso_datetime(value: str | None) -> datetime | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO datetime: {value}") from exc


def parse_db_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    text = str(value)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        # SQLite may store "YYYY-MM-DD HH:MM:SS(.ffffff)".
        try:
            return datetime.strptime(text.split("+")[0], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return datetime.strptime(text.split("+")[0], "%Y-%m-%d %H:%M:%S")


def load_details(raw: Any) -> dict[str, Any]:
    if raw in (None, ""):
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def coerce_probability(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        probability = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, probability))


def coerce_is_anomaly(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "anomaly", "attack"}:
        return True
    if text in {"0", "false", "no", "normal", "benign"}:
        return False
    return None


def first_probability(*values: Any) -> float | None:
    for value in values:
        probability = coerce_probability(value)
        if probability is not None:
            return probability
    return None


def ensure_anomaly_logs_schema(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='anomaly_logs'"
    ).fetchone()
    if table is None:
        raise RuntimeError("Required table 'anomaly_logs' does not exist in the SQLite database.")

    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(anomaly_logs)").fetchall()
    }
    missing = sorted(REQUIRED_COLUMNS - columns)
    if missing:
        raise RuntimeError(
            "Table 'anomaly_logs' is missing required column(s): "
            + ", ".join(missing)
        )


def export_events(db_path: Path, output_path: Path, start: datetime | None, end: datetime | None) -> int:
    if not db_path.exists():
        raise FileNotFoundError(f"SQLite database not found: {db_path}")

    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    try:
        ensure_anomaly_logs_schema(connection)
        rows = connection.execute(
            "SELECT timestamp, device_ip, score, details FROM anomaly_logs ORDER BY timestamp ASC"
        ).fetchall()
    finally:
        connection.close()

    output_rows: list[dict[str, Any]] = []
    for row in rows:
        timestamp = parse_db_timestamp(row["timestamp"])
        if start is not None and timestamp < start:
            continue
        if end is not None and timestamp > end:
            continue

        details = load_details(row["details"])
        model = details.get("model") if isinstance(details.get("model"), dict) else {}

        attack_probability = first_probability(
            details.get("attack_probability"),
            model.get("attack_probability"),
            details.get("anomaly_score"),
            details.get("score"),
            row["score"],
        )
        if attack_probability is None:
            continue

        is_anomaly = (
            coerce_is_anomaly(details.get("is_anomaly"))
            if "is_anomaly" in details
            else coerce_is_anomaly(model.get("is_anomaly"))
        )
        if is_anomaly is None:
            is_anomaly = attack_probability >= 0.5

        output_rows.append({
            "timestamp": timestamp.isoformat(),
            "device_ip": row["device_ip"],
            "attack_probability": attack_probability,
            "is_anomaly": str(bool(is_anomaly)).lower(),
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(output_rows)
    return len(output_rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export Sentinel-IoT live anomaly events from SQLite.")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--start", default=None, help="Optional ISO datetime lower bound.")
    parser.add_argument("--end", default=None, help="Optional ISO datetime upper bound.")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        count = export_events(
            db_path=args.db_path,
            output_path=args.output,
            start=parse_iso_datetime(args.start),
            end=parse_iso_datetime(args.end),
        )
    except Exception as exc:
        print(f"[ERROR] Live event export failed: {exc}")
        return 1

    print(json.dumps({
        "status": "ok",
        "db_path": str(args.db_path),
        "output": str(args.output),
        "event_count": count,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
