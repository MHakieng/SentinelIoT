"""Rule-based device classifier for device-class-aware detection.

The classifier is deliberately independent from the database, scanner service,
monitor service, and model routing. It only turns a device dict plus optional
flow summary into an explainable class prediction.
"""

from __future__ import annotations

from typing import Any

from sentinel_iot.ml.device_feature_builder import build_device_features


DEVICE_CLASSES = {"iot_device", "client_device", "network_infrastructure", "unknown"}

IOT_TEXT_KEYWORDS = (
    "tuya",
    "hikvision",
    "dahua",
    "espresif",
    "espressif",
    "philips hue",
    "xiaomi smart",
    "sonoff",
    "shelly",
    "raspberry pi",
    "axis",
    "reolink",
    "mqtt",
    "rtsp",
    "camera",
    "ip camera",
    "dvr",
    "nvr",
    "coap",
    "modbus",
)
IOT_PORTS = {1883, 8883, 554, 5683, 502, 34567, 37777}

CLIENT_TEXT_KEYWORDS = (
    "microsoft",
    "apple",
    "samsung",
    "lenovo",
    "dell",
    "hewlett",
    "hp",
    "asus",
    "acer",
    "intel",
    "realtek",
    "qualcomm",
    "oneplus",
    "huawei",
    "xiaomi phone",
    "desktop",
    "laptop",
    "macbook",
    "iphone",
    "android",
    "windows",
)

INFRA_TEXT_KEYWORDS = (
    "router",
    "gateway",
    "modem",
    "access point",
    "mikrotik",
    "tp-link",
    "tplink",
    "ubiquiti",
    "openwrt",
    "pfsense",
    "zyxel",
    "keenetic",
    "netgear",
    "d-link",
    "linksys",
    "cisco",
    "upnp",
    "dns",
    "dhcp",
    "snmp",
    "mdns",
    "ssdp",
)
INFRA_PORTS = {53, 67, 68, 161, 1900, 5353}


def _clamp(value: float, min_value: float = 0.0, max_value: float = 1.0) -> float:
    return float(max(min_value, min(max_value, value)))


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in text for keyword in keywords)


def _combined_text(features: dict[str, Any]) -> str:
    return " ".join(
        str(features.get(key, ""))
        for key in (
            "vendor_text",
            "hostname_text",
            "service_text",
            "http_title_text",
            "server_header_text",
            "product_text",
        )
    ).lower()


def _score_iot(features: dict[str, Any]) -> tuple[float, list[str]]:
    text = _combined_text(features)
    ports = set(features.get("open_ports_set") or set())
    score = 0.0
    evidence: list[str] = []

    if _contains_any(text, IOT_TEXT_KEYWORDS):
        score += 2.5
        evidence.append("Vendor or service text suggests IoT/camera/embedded device")

    matched_ports = sorted(ports & IOT_PORTS)
    if matched_ports:
        score += 2.0
        evidence.append(f"IoT-specific port(s) observed: {', '.join(map(str, matched_ports))}")

    if features.get("mqtt_ratio", 0.0) >= 0.10:
        score += 1.0
        evidence.append("MQTT traffic ratio suggests IoT telemetry")

    if features.get("rtsp_ratio", 0.0) >= 0.10:
        score += 1.0
        evidence.append("RTSP traffic ratio suggests camera stream")

    return score, evidence


def _score_client(features: dict[str, Any]) -> tuple[float, list[str]]:
    text = _combined_text(features)
    ports = set(features.get("open_ports_set") or set())
    score = 0.0
    evidence: list[str] = []

    if _contains_any(text, CLIENT_TEXT_KEYWORDS):
        score += 2.5
        evidence.append("Vendor or hostname suggests PC/mobile client device")

    has_browser_pattern = (
        features.get("https_ratio", 0.0) >= 0.45
        and (features.get("dns_ratio", 0.0) > 0.0 or features.get("quic_ratio", 0.0) > 0.0)
    )
    if has_browser_pattern and not (ports & IOT_PORTS):
        score += 2.5
        evidence.append("High HTTPS/DNS/QUIC traffic ratio without IoT-specific ports")

    if features.get("unique_dst_ips", 0) >= 20:
        score += 0.8
        evidence.append("Many unique destinations resemble browser/client traffic")

    if features.get("unique_dst_ports", 0) >= 8 and not (ports & IOT_PORTS):
        score += 0.4
        evidence.append("Multiple destination ports observed for client activity")

    return score, evidence


def _score_infrastructure(features: dict[str, Any]) -> tuple[float, list[str]]:
    text = _combined_text(features)
    ports = set(features.get("open_ports_set") or set())
    score = 0.0
    evidence: list[str] = []

    if _contains_any(text, INFRA_TEXT_KEYWORDS):
        score += 3.0
        evidence.append("Vendor, hostname, or service text suggests network infrastructure")

    matched_ports = sorted(ports & INFRA_PORTS)
    if matched_ports:
        score += min(2.4, len(matched_ports) * 0.8)
        evidence.append(f"Infrastructure service port(s) observed: {', '.join(map(str, matched_ports))}")

    if (features.get("has_80") or features.get("has_443") or features.get("has_8080")) and score > 0:
        score += 0.5
        evidence.append("Web administration surface is consistent with infrastructure devices")

    return score, evidence


def _normalize_confidence(score: float) -> float:
    return _clamp(score / 5.0)


def classify_device(device: dict, flow_summary: dict | None = None) -> dict:
    """Classify a device into iot/client/infrastructure/unknown using rules."""
    features = build_device_features(device if isinstance(device, dict) else {}, flow_summary)
    scored = {
        "iot_device": _score_iot(features),
        "client_device": _score_client(features),
        "network_infrastructure": _score_infrastructure(features),
    }
    ranked = sorted(
        ((device_class, score, evidence) for device_class, (score, evidence) in scored.items()),
        key=lambda item: item[1],
        reverse=True,
    )

    winner, winning_score, evidence = ranked[0]
    runner_up, runner_score, runner_evidence = ranked[1]
    conflict = winning_score > 0 and runner_score > 0 and runner_score >= 2.0

    if winning_score < 1.5:
        return {
            "device_class": "unknown",
            "confidence": 0.2,
            "evidence": ["Insufficient scanner evidence", "No distinctive service or vendor signal"],
            "method": "rule_based",
        }

    confidence = _normalize_confidence(winning_score)
    output_evidence = list(evidence)
    if conflict:
        confidence *= 0.70
        output_evidence.append(
            f"Conflicting device class signals also suggest {runner_up}: {runner_evidence[0] if runner_evidence else 'mixed evidence'}"
        )

    return {
        "device_class": winner if winner in DEVICE_CLASSES else "unknown",
        "confidence": round(_clamp(confidence), 2),
        "evidence": output_evidence or ["No distinctive service or vendor signal"],
        "method": "rule_based",
    }


__all__ = ["classify_device"]
