"""Explainable runtime scoring for live Sentinel-IoT flows."""

from __future__ import annotations

import math
from typing import Any, Mapping


RISKY_OR_PLAINTEXT_PORTS = {21, 23, 80, 1883, 2323}
TELNET_LIKE_PORTS = {23, 2323}
ENCRYPTED_SERVICE_PORTS = {443, 8883}
SERVICE_CONTEXT_PORTS = RISKY_OR_PLAINTEXT_PORTS | TELNET_LIKE_PORTS | ENCRYPTED_SERVICE_PORTS


def clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    numeric = _to_float(value, default=minimum)
    return float(max(minimum, min(maximum, numeric)))


def classify_severity(score: float) -> str:
    bounded = clamp(score)
    if bounded < 35:
        return "low"
    if bounded < 60:
        return "medium"
    if bounded < 80:
        return "high"
    return "critical"


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or isinstance(value, bool):
            return default
        numeric = float(value)
        return numeric if math.isfinite(numeric) else default
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or isinstance(value, bool):
            return default
        return int(value)
    except (OverflowError, TypeError, ValueError):
        return default


def _protocol_name(protocol: Any) -> str:
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    if isinstance(protocol, str):
        upper = protocol.upper()
        return upper if upper in {"TCP", "UDP", "ICMP"} else "UNKNOWN"
    return protocol_map.get(_to_int(protocol, -1), "UNKNOWN")


def _service_port(flow: Mapping[str, Any]) -> int:
    """Return the most meaningful service port for bidirectional live flows."""
    src_port = _to_int(flow.get("src_port"))
    dst_port = _to_int(flow.get("dst_port"))
    if dst_port in SERVICE_CONTEXT_PORTS:
        return dst_port
    if src_port in SERVICE_CONTEXT_PORTS:
        return src_port
    return dst_port


def _flow_features(flow: Mapping[str, Any]) -> dict[str, float]:
    nested_features = flow.get("features")
    features = nested_features if isinstance(nested_features, Mapping) else {}

    def pick(name: str, fallback: Any = None) -> Any:
        return flow.get(name, features.get(name, fallback))

    packet_count = _to_float(pick("packet_count"))
    byte_count = _to_float(pick("byte_count"))
    duration = _to_float(pick("duration"))
    packets_per_second = _to_float(pick("packets_per_second", pick("packet_rate")))
    if packets_per_second == 0.0 and duration > 0:
        packets_per_second = packet_count / duration

    bytes_per_second = _to_float(pick("bytes_per_second"))
    if bytes_per_second == 0.0 and duration > 0:
        bytes_per_second = byte_count / duration

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "avg_packet_size": _to_float(pick("avg_packet_size")),
        "mean_iat": _to_float(pick("mean_iat")),
        "var_iat": _to_float(pick("var_iat")),
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
    }


def _model_score_from_flow(flow: Mapping[str, Any]) -> float:
    return _to_float(
        flow.get(
            "ml_anomaly_score",
            flow.get("anomaly_score", flow.get("attack_probability")),
        )
    )


def _raw_score_from_flow(flow: Mapping[str, Any]) -> float:
    return _to_float(
        flow.get(
            "ml_raw_score",
            flow.get("raw_score", flow.get("anomaly_score", flow.get("attack_probability"))),
        )
    )


def score_flow(flow: Mapping[str, Any], ml_raw_score: float, ml_anomaly_score: float) -> dict[str, Any]:
    features = _flow_features(flow)
    anomaly_score = clamp(_to_float(ml_anomaly_score), 0.0, 1.0)
    raw_score = _to_float(ml_raw_score)
    dst_port = _to_int(flow.get("dst_port"))
    service_port = _service_port(flow)
    protocol = _protocol_name(flow.get("protocol_name", flow.get("protocol")))
    reward_points = 0
    penalty_points = 0
    reasons: list[str] = []

    if anomaly_score >= 0.80:
        penalty_points += 25
        reasons.append("High ML anomaly score")
    elif anomaly_score >= 0.60:
        penalty_points += 15
        reasons.append("Elevated ML anomaly score")

    if features["packets_per_second"] >= 100:
        penalty_points += 15
        reasons.append("Very high packet rate")
    elif features["packets_per_second"] >= 50:
        penalty_points += 10
        reasons.append("High packet rate")

    if 0 < features["mean_iat"] < 0.02:
        penalty_points += 10
        reasons.append("Very low inter-arrival time / burst traffic")

    if service_port in RISKY_OR_PLAINTEXT_PORTS:
        penalty_points += 10
        reasons.append("Risky or plaintext destination port")

    if service_port in TELNET_LIKE_PORTS:
        penalty_points += 10
        reasons.append("Telnet-like insecure access pattern")

    if features["byte_count"] >= 1_000_000 and 0 < features["duration"] <= 2.0:
        penalty_points += 10
        reasons.append("Short-duration high-volume transfer pattern")

    if anomaly_score < 0.20:
        reward_points += 15
        reasons.append("Low ML anomaly score")

    if features["packets_per_second"] < 10 and anomaly_score < 0.30:
        reward_points += 7
        reasons.append("Stable low-volume traffic pattern")

    if service_port in ENCRYPTED_SERVICE_PORTS and anomaly_score < 0.55:
        reward_points += 8
        reasons.append("Expected encrypted service port")

    if features["mean_iat"] >= 0.02 and features["var_iat"] <= 0.001:
        reward_points += 5
        reasons.append("Stable inter-arrival timing")

    base_score = anomaly_score * 100.0
    final_flow_risk = clamp(base_score + penalty_points - reward_points)

    return {
        "flow_id": str(flow.get("flow_id") or ""),
        "src_ip": str(flow.get("src_ip") or ""),
        "dst_ip": str(flow.get("dst_ip") or ""),
        "src_port": _to_int(flow.get("src_port")),
        "dst_port": dst_port,
        "protocol": protocol,
        "features": features,
        "ml_raw_score": raw_score,
        "ml_anomaly_score": anomaly_score,
        "reward_points": int(reward_points),
        "penalty_points": int(penalty_points),
        "final_flow_risk": round(final_flow_risk, 2),
        "severity": classify_severity(final_flow_risk),
        "reasons": reasons,
    }


def score_flows(flows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        score_flow(
            flow,
            ml_raw_score=_raw_score_from_flow(flow),
            ml_anomaly_score=_model_score_from_flow(flow),
        )
        for flow in flows
    ]
