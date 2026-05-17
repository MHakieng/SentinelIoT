"""Feature normalization helpers for device-class-aware detection.

This module is intentionally standalone. It does not read from the database,
call scanner services, or modify runtime scoring behavior.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


PORTS_OF_INTEREST = (
    22,
    23,
    53,
    67,
    68,
    80,
    443,
    445,
    554,
    161,
    1883,
    8883,
    1900,
    5353,
    5683,
    8080,
    502,
    3389,
    34567,
    37777,
)


def _safe_text(value: Any) -> str:
    """Return a lowercase text representation without raising on malformed input."""
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_safe_text(item) for item in value if item is not None).strip()
    if isinstance(value, Mapping):
        return " ".join(_safe_text(item) for item in value.values() if item is not None).strip()
    return str(value).strip().lower()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or isinstance(value, bool):
            return default
        numeric = float(value)
        return numeric if numeric == numeric and numeric not in (float("inf"), float("-inf")) else default
    except (TypeError, ValueError):
        return default


def _safe_ratio(value: Any) -> float:
    return max(0.0, min(1.0, _safe_float(value)))


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or isinstance(value, bool):
            return None
        return int(value)
    except (OverflowError, TypeError, ValueError):
        return None


def _safe_count(value: Any) -> int:
    parsed = _safe_int(value)
    return max(0, parsed or 0)


def _extract_open_ports(device: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize open_ports from list, dict, string, or malformed values."""
    raw_ports = device.get("open_ports") if isinstance(device, Mapping) else None
    if raw_ports is None:
        return []

    if isinstance(raw_ports, Mapping):
        raw_items = [raw_ports]
    elif isinstance(raw_ports, list):
        raw_items = raw_ports
    elif isinstance(raw_ports, tuple):
        raw_items = list(raw_ports)
    elif isinstance(raw_ports, str):
        raw_items = [{"port": match} for match in re.findall(r"\d+", raw_ports)]
    else:
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw_items:
        if isinstance(item, Mapping):
            port = _safe_int(item.get("port"))
            if port is None:
                continue
            normalized.append(dict(item, port=port))
            continue

        port = _safe_int(item)
        if port is not None:
            normalized.append({"port": port})

    return normalized


def build_device_features(device: dict, flow_summary: dict | None = None) -> dict:
    """Build normalized device classification features from scanner and flow data."""
    device_map = device if isinstance(device, Mapping) else {}
    flow_map = flow_summary if isinstance(flow_summary, Mapping) else {}
    open_ports = _extract_open_ports(device_map)
    open_ports_set = {port["port"] for port in open_ports}

    service_text = _safe_text([port.get("service") for port in open_ports])
    http_title_text = _safe_text([port.get("http_title") for port in open_ports])
    server_header_text = _safe_text([port.get("server_header") for port in open_ports])
    product_text = _safe_text([
        port.get("product") or port.get("version") or port.get("extrainfo") or port.get("banner")
        for port in open_ports
    ])

    features = {
        "vendor_text": _safe_text(device_map.get("vendor")),
        "hostname_text": _safe_text(device_map.get("hostname")),
        "service_text": service_text,
        "http_title_text": http_title_text,
        "server_header_text": server_header_text,
        "product_text": product_text,
        "open_ports_set": open_ports_set,
        "open_port_count": len(open_ports_set),
        "https_ratio": _safe_ratio(flow_map.get("https_ratio")),
        "dns_ratio": _safe_ratio(flow_map.get("dns_ratio")),
        "quic_ratio": _safe_ratio(flow_map.get("quic_ratio")),
        "mqtt_ratio": _safe_ratio(flow_map.get("mqtt_ratio")),
        "rtsp_ratio": _safe_ratio(flow_map.get("rtsp_ratio")),
        "unique_dst_ips": _safe_count(flow_map.get("unique_dst_ips")),
        "unique_dst_ports": _safe_count(flow_map.get("unique_dst_ports")),
        "total_flows": _safe_count(flow_map.get("total_flows")),
        "total_packets": _safe_count(flow_map.get("total_packets")),
        "total_bytes": _safe_count(flow_map.get("total_bytes")),
    }

    for port in PORTS_OF_INTEREST:
        features[f"has_{port}"] = port in open_ports_set

    return features


__all__ = ["build_device_features"]
