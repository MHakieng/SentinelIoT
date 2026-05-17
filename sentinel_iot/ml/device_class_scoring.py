"""Device-class-aware calibration for live flow scoring."""

from __future__ import annotations

import math
from typing import Any, Mapping

from sentinel_iot.ml.flow_scorer import classify_severity, clamp, score_flow


DEVICE_CLASSES = {"iot_device", "client_device", "network_infrastructure", "unknown"}
CLIENT_COMMON_PORTS = {53, 80, 443}
CLIENT_QUIC_PORTS = {443}
CLIENT_RISKY_PORTS = {23, 2323, 445, 3389}
INFRASTRUCTURE_SERVICE_PORTS = {53, 67, 68, 161, 1900, 5353}
IOT_EXPECTED_SERVICE_PORTS = {554, 1883, 8883, 5683}
TELNET_LIKE_PORTS = {23, 2323}
COMMON_SERVICE_PORTS = CLIENT_COMMON_PORTS | CLIENT_RISKY_PORTS | IOT_EXPECTED_SERVICE_PORTS | INFRASTRUCTURE_SERVICE_PORTS

CLASS_THRESHOLDS = {
    "iot_device": 0.60,
    "client_device": 0.75,
    "network_infrastructure": 0.70,
    "unknown": 0.65,
}


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


def _normalize_device_class(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower()
    return normalized if normalized in DEVICE_CLASSES else "unknown"


def _protocol_name(value: Any) -> str:
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    if isinstance(value, str):
        upper = value.upper()
        return upper if upper in {"TCP", "UDP", "ICMP"} else "UNKNOWN"
    return protocol_map.get(_to_int(value, -1), "UNKNOWN")


def _service_port(flow: Mapping[str, Any], base_score: Mapping[str, Any]) -> int:
    src_port = _to_int(flow.get("src_port", base_score.get("src_port")))
    dst_port = _to_int(flow.get("dst_port", base_score.get("dst_port")))
    if dst_port in COMMON_SERVICE_PORTS:
        return dst_port
    if src_port in COMMON_SERVICE_PORTS:
        return src_port
    return dst_port


def classify_decision(score: Mapping[str, Any], device_class: str) -> tuple[str, str]:
    final_risk = _to_float(score.get("final_flow_risk"))
    anomaly_score = _to_float(score.get("ml_anomaly_score"))
    penalty_points = _to_int(score.get("penalty_points"))
    class_threshold = CLASS_THRESHOLDS.get(device_class, CLASS_THRESHOLDS["unknown"])

    if final_risk >= 80 and anomaly_score >= class_threshold and penalty_points >= 25:
        return "anomaly", "class_aware_scoring"
    if final_risk >= 60 or score.get("class_aware_reasons"):
        return "suspicious", "class_aware_scoring"
    return "normal", "class_aware_scoring"


def apply_device_class_context(
    base_score: Mapping[str, Any],
    flow: Mapping[str, Any],
    source_device_class: str = "unknown",
    destination_device_class: str = "unknown",
    source_confidence: float | None = None,
    destination_confidence: float | None = None,
) -> dict[str, Any]:
    source_class = _normalize_device_class(source_device_class)
    destination_class = _normalize_device_class(destination_device_class)
    protocol = _protocol_name(flow.get("protocol_name", flow.get("protocol", base_score.get("protocol"))))
    dst_port = _to_int(flow.get("dst_port", base_score.get("dst_port")))
    service_port = _service_port(flow, base_score)
    anomaly_score = _to_float(base_score.get("ml_anomaly_score"))
    features = base_score.get("features") if isinstance(base_score.get("features"), Mapping) else {}
    byte_count = _to_float(features.get("byte_count", flow.get("byte_count")))
    duration = _to_float(features.get("duration", flow.get("duration")))

    adjustment = 0.0
    class_reasons: list[str] = []

    client_context = source_class == "client_device" or destination_class == "client_device"
    if client_context:
        if service_port in CLIENT_COMMON_PORTS:
            adjustment -= 28 if anomaly_score >= 0.70 else 18
            class_reasons.append("Client device common web/DNS traffic context")
        if protocol == "UDP" and service_port in CLIENT_QUIC_PORTS:
            adjustment -= 12
            class_reasons.append("Client device QUIC traffic context")
        if service_port in CLIENT_RISKY_PORTS:
            adjustment += 15
            class_reasons.append("Client device risky administrative or lateral movement port")
    elif source_class == "network_infrastructure":
        if service_port in INFRASTRUCTURE_SERVICE_PORTS and anomaly_score < 0.65:
            adjustment -= 8
            class_reasons.append("Network infrastructure expected service traffic context")
        if service_port in CLIENT_RISKY_PORTS and anomaly_score >= 0.50:
            adjustment += 10
            class_reasons.append("Network infrastructure risky management port activity")
    elif source_class == "iot_device":
        if service_port in IOT_EXPECTED_SERVICE_PORTS and anomaly_score < 0.60:
            adjustment -= 6
            class_reasons.append("IoT device expected service traffic context")
        if service_port in TELNET_LIKE_PORTS:
            adjustment += 10
            class_reasons.append("IoT device Telnet-like insecure access context")
        if byte_count >= 1_000_000 and 0 < duration <= 2.0:
            adjustment += 8
            class_reasons.append("IoT device short-duration high-volume transfer context")
    else:
        class_reasons.append("Unknown device context; conservative scoring applied")

    result = dict(base_score)
    result["source_device_class"] = source_class
    result["destination_device_class"] = destination_class
    result["source_device_class_confidence"] = source_confidence
    result["destination_device_class_confidence"] = destination_confidence
    result["class_aware_adjustment"] = round(adjustment, 2)
    result["class_aware_reasons"] = class_reasons

    original_reasons = list(result.get("reasons") or [])
    result["reasons"] = original_reasons + class_reasons
    final_flow_risk = clamp(_to_float(result.get("final_flow_risk")) + adjustment)
    result["final_flow_risk"] = round(final_flow_risk, 2)
    result["severity"] = classify_severity(final_flow_risk)

    decision, decision_source = classify_decision(result, source_class)
    result["decision"] = decision
    result["decision_source"] = decision_source
    return result


def score_flow_with_device_context(
    flow: Mapping[str, Any],
    ml_raw_score: float,
    ml_anomaly_score: float,
) -> dict[str, Any]:
    base_score = score_flow(flow, ml_raw_score=ml_raw_score, ml_anomaly_score=ml_anomaly_score)
    return apply_device_class_context(
        base_score,
        flow,
        source_device_class=str(flow.get("source_device_class", "unknown")),
        destination_device_class=str(flow.get("destination_device_class", "unknown")),
        source_confidence=flow.get("source_device_class_confidence"),
        destination_confidence=flow.get("destination_device_class_confidence"),
    )
