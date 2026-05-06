"""Collect live Sentinel-IoT monitor flows into an evaluation CSV."""

from __future__ import annotations

import argparse
import time
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LIVE_DIR = PROJECT_ROOT / "evaluation" / "live"
DEFAULT_OUTPUT = LIVE_DIR / "live_flow_snapshots.csv"
FLOW_FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "avg_packet_size",
    "mean_iat",
    "var_iat",
]
FLOW_METADATA_COLUMNS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "protocol_name",
    "anomaly_score",
    "model_label",
    "confidence",
]
OUTPUT_COLUMNS = [
    "collected_at",
    *FLOW_METADATA_COLUMNS,
    *FLOW_FEATURE_COLUMNS,
    "manual_label",
    "attack_type",
    "notes",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sentinel-IoT canli monitor flow snapshotlarini CSV'ye toplar.")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--duration-seconds", type=int, default=60)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--request-timeout", type=float, default=5.0)
    parser.add_argument(
        "--start-monitor",
        action="store_true",
        help="Toplama basinda pasif canli monitor endpointini baslatir.",
    )
    parser.add_argument(
        "--monitor-window-seconds",
        type=int,
        default=10,
        help="--start-monitor kullanilirsa backend capture window suresi.",
    )
    return parser


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_flow(flow: dict, collected_at: str) -> dict:
    row = {column: flow.get(column) for column in FLOW_METADATA_COLUMNS + FLOW_FEATURE_COLUMNS}
    row["collected_at"] = collected_at
    row["model_label"] = flow.get("label", 0)
    row["manual_label"] = ""
    row["attack_type"] = ""
    row["notes"] = ""
    return {column: row.get(column, "") for column in OUTPUT_COLUMNS}


def start_monitor(api_base_url: str, timeout: float, window_seconds: int) -> None:
    url = f"{api_base_url.rstrip('/')}/monitor/live/start"
    response = requests.post(url, params={"duration": window_seconds}, timeout=timeout)
    if response.status_code >= 400:
        raise RuntimeError(f"Monitor baslatilamadi: HTTP {response.status_code} - {response.text}")
    print(f"[OK] Canli monitor baslatma istegi gonderildi: {response.json()}")


def fetch_flows(api_base_url: str, timeout: float) -> list[dict]:
    url = f"{api_base_url.rstrip('/')}/monitor/flows"
    response = requests.get(url, timeout=timeout)
    if response.status_code >= 400:
        raise RuntimeError(f"Flow snapshot alinamadi: HTTP {response.status_code} - {response.text}")
    payload = response.json()
    if not isinstance(payload, list):
        raise RuntimeError("/monitor/flows beklenen liste formatinda donmedi.")
    return payload


def main() -> int:
    args = build_parser().parse_args()
    if args.duration_seconds <= 0:
        print("[HATA] --duration-seconds pozitif olmali.")
        return 1
    if args.interval_seconds <= 0:
        print("[HATA] --interval-seconds pozitif olmali.")
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    seen_keys = set()
    try:
        if args.start_monitor:
            start_monitor(args.api_base_url, args.request_timeout, args.monitor_window_seconds)

        deadline = time.time() + args.duration_seconds
        while time.time() < deadline:
            collected_at = utc_now()
            flows = fetch_flows(args.api_base_url, args.request_timeout)
            for flow in flows:
                row = normalize_flow(flow, collected_at)
                key = (
                    row.get("collected_at"),
                    row.get("flow_id"),
                    row.get("packet_count"),
                    row.get("byte_count"),
                    row.get("model_label"),
                    row.get("anomaly_score"),
                )
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                rows.append(row)
            print(f"[INFO] {collected_at}: {len(flows)} flow goruldu, toplam {len(rows)} satir")
            time.sleep(args.interval_seconds)

        df = pd.DataFrame(rows, columns=OUTPUT_COLUMNS)
        df.to_csv(args.output, index=False)
    except Exception as exc:
        print(f"[HATA] Canli flow toplama basarisiz: {exc}")
        return 1

    print(f"[OK] Canli flow snapshot CSV yazildi: {args.output}")
    if not rows:
        print("[UYARI] Hic flow toplanmadi. Backend calisiyor mu, monitor baslatildi mi ve agda trafik var mi kontrol edin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
