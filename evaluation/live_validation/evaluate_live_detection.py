"""Evaluate labelled live anomaly detection events against manual time windows.

This harness computes live precision/recall/F1 only when the user provides
manually labelled time windows. It does not infer ground truth automatically and
does not modify Sentinel-IoT runtime components.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSON_REPORT = PROJECT_ROOT / "evaluation" / "results" / "live_detection_validation_report.json"
DEFAULT_MD_REPORT = PROJECT_ROOT / "evaluation" / "results" / "live_detection_validation_report.md"
DISCLAIMER = (
    "Bu rapor kucuk olcekli kontrollu canli demo dogrulamasidir; "
    "genis saha basarisi garantisi degildir."
)


def parse_timestamp(value: Any) -> datetime:
    if value is None or str(value).strip() == "":
        raise ValueError("timestamp value is required")
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO timestamp: {value}") from exc


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Events file not found: {path}")
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = data.get("events", [])
        if not isinstance(data, list):
            raise ValueError("JSON events input must be a list or an object with an 'events' list.")
        return [dict(item) for item in data]
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    raise ValueError("Events input must be .json or .csv")


def load_windows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Windows file not found: {path}")
    windows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(windows, list):
        raise ValueError("Windows JSON must be a list.")

    parsed = []
    for index, window in enumerate(windows):
        label_text = str(window.get("label", "")).strip().lower()
        if label_text not in {"benign", "attack"}:
            raise ValueError(f"Window {index} label must be 'benign' or 'attack'.")
        start = parse_timestamp(window.get("start"))
        end = parse_timestamp(window.get("end"))
        if end <= start:
            raise ValueError(f"Window {index} end must be after start.")
        parsed.append({
            "index": index,
            "start": start,
            "end": end,
            "label": label_text,
            "target": 1 if label_text == "attack" else 0,
            "scenario": window.get("scenario", ""),
        })
    return parsed


def parse_bool_prediction(event: dict[str, Any], threshold: float) -> tuple[int, float | None]:
    probability = event.get("attack_probability")
    if probability in (None, ""):
        probability = event.get("anomaly_score", event.get("score"))
    probability_float = None
    if probability not in (None, ""):
        probability_float = float(probability)

    raw = event.get("is_anomaly")
    if raw in (None, ""):
        if probability_float is None:
            raise ValueError("Event must include is_anomaly or attack_probability/anomaly_score/score.")
        return int(probability_float >= threshold), probability_float

    if isinstance(raw, bool):
        return int(raw), probability_float
    raw_text = str(raw).strip().lower()
    if raw_text in {"1", "true", "yes", "anomaly", "attack"}:
        return 1, probability_float
    if raw_text in {"0", "false", "no", "normal", "benign"}:
        return 0, probability_float
    raise ValueError(f"Invalid is_anomaly value: {raw}")


def find_window(timestamp: datetime, windows: list[dict[str, Any]]) -> dict[str, Any] | None:
    for window in windows:
        if window["start"] <= timestamp < window["end"]:
            return window
    return None


def confusion_counts(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def compute_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    counts = confusion_counts(y_true, y_pred)
    tp, tn, fp, fn = counts["tp"], counts["tn"], counts["fp"], counts["fn"]
    total = max(1, len(y_true))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2 * precision * recall / max(1e-12, precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "accuracy": (tp + tn) / total,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "false_positive_count": fp,
        "false_negative_count": fn,
    }


def summarize_probabilities(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None}
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
    }


def evaluate(events_path: Path, windows_path: Path, threshold: float) -> dict[str, Any]:
    events = load_events(events_path)
    windows = load_windows(windows_path)

    y_true: list[int] = []
    y_pred: list[int] = []
    matched_events: list[dict[str, Any]] = []
    unmatched_events: list[dict[str, Any]] = []
    event_count_by_window: Counter[str] = Counter()
    probabilities_by_window: dict[str, list[float]] = defaultdict(list)

    for event_index, event in enumerate(events):
        timestamp = parse_timestamp(event.get("timestamp"))
        window = find_window(timestamp, windows)
        if window is None:
            unmatched_events.append({
                "event_index": event_index,
                "timestamp": event.get("timestamp"),
                "reason": "outside_labelled_windows",
            })
            continue

        prediction, probability = parse_bool_prediction(event, threshold)
        y_true.append(window["target"])
        y_pred.append(prediction)

        window_key = f"{window['index']}:{window['scenario'] or window['label']}"
        event_count_by_window[window_key] += 1
        if probability is not None:
            probabilities_by_window[window_key].append(probability)

        matched_events.append({
            "event_index": event_index,
            "timestamp": event.get("timestamp"),
            "device_ip": event.get("device_ip"),
            "flow_id": event.get("flow_id"),
            "window_index": window["index"],
            "scenario": window["scenario"],
            "ground_truth": window["target"],
            "prediction": prediction,
            "attack_probability": probability,
        })

    if not y_true:
        raise ValueError("No events matched labelled windows; cannot compute metrics.")

    report = {
        "events_file": str(events_path),
        "windows_file": str(windows_path),
        "threshold": threshold,
        "matched_event_count": len(matched_events),
        "unmatched_event_count": len(unmatched_events),
        "metrics": compute_metrics(y_true, y_pred),
        "event_count_by_window": {key: int(value) for key, value in sorted(event_count_by_window.items())},
        "attack_probability_summary_by_window": {
            key: summarize_probabilities(values)
            for key, values in sorted(probabilities_by_window.items())
        },
        "windows": [
            {
                "index": window["index"],
                "start": window["start"].isoformat(),
                "end": window["end"].isoformat(),
                "label": window["label"],
                "scenario": window["scenario"],
            }
            for window in windows
        ],
        "unmatched_events": unmatched_events,
        "disclaimer": DISCLAIMER,
    }
    return report


def write_markdown(report: dict[str, Any], output_path: Path) -> None:
    metrics = report["metrics"]
    lines = [
        "# Live Detection Validation Report",
        "",
        DISCLAIMER,
        "",
        "## Inputs",
        "",
        f"- Events: `{report['events_file']}`",
        f"- Windows: `{report['windows_file']}`",
        f"- Threshold: `{report['threshold']}`",
        "",
        "## Event Matching",
        "",
        f"- Matched events: {report['matched_event_count']}",
        f"- Unmatched events: {report['unmatched_event_count']}",
        "",
        "## Metrics",
        "",
        f"- Accuracy: {metrics['accuracy']}",
        f"- Precision: {metrics['precision']}",
        f"- Recall: {metrics['recall']}",
        f"- F1: {metrics['f1']}",
        f"- Confusion matrix [[TN, FP], [FN, TP]]: {metrics['confusion_matrix']}",
        f"- False positives: {metrics['false_positive_count']}",
        f"- False negatives: {metrics['false_negative_count']}",
        "",
        "## Events By Window",
        "",
    ]
    for key, value in report["event_count_by_window"].items():
        lines.append(f"- {key}: {value}")

    lines.extend(["", "## Attack Probability Summary By Window", ""])
    for key, summary in report["attack_probability_summary_by_window"].items():
        lines.append(
            f"- {key}: count={summary['count']}, min={summary['min']}, "
            f"max={summary['max']}, mean={summary['mean']}, median={summary['median']}"
        )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate live anomaly events against labelled time windows.")
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--output-json", type=Path, default=DEFAULT_JSON_REPORT)
    parser.add_argument("--output-md", type=Path, default=DEFAULT_MD_REPORT)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = evaluate(args.events, args.windows, args.threshold)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, args.output_md)
    print(json.dumps({
        "status": "ok",
        "matched_event_count": report["matched_event_count"],
        "unmatched_event_count": report["unmatched_event_count"],
        "metrics": report["metrics"],
        "output_json": str(args.output_json),
        "output_md": str(args.output_md),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
