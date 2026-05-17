from sentinel_iot.ml.device_classifier import DEVICE_CLASSES, classify_device
from sentinel_iot.ml.device_feature_builder import build_device_features


def test_iot_camera_is_classified_with_high_confidence():
    result = classify_device({
        "ip": "192.168.1.30",
        "vendor": "Hikvision",
        "hostname": "cam-frontdoor",
        "open_ports": [
            {"port": 80, "service": "http", "http_title": "Hikvision IP Camera"},
            {"port": 554, "service": "rtsp", "product": "camera stream"},
        ],
    })

    assert result["device_class"] == "iot_device"
    assert result["confidence"] >= 0.70
    assert result["evidence"]


def test_mqtt_sensor_is_classified_as_iot_device():
    result = classify_device({
        "ip": "192.168.1.31",
        "vendor": "Espressif IoT Node",
        "open_ports": [{"port": 1883, "service": "mqtt"}],
    })

    assert result["device_class"] == "iot_device"
    assert result["confidence"] >= 0.70


def test_windows_laptop_is_classified_as_client_device():
    result = classify_device(
        {
            "ip": "192.168.1.20",
            "vendor": "Intel Corporate",
            "hostname": "DESKTOP-HAKIT",
            "open_ports": [],
        },
        {
            "https_ratio": 0.72,
            "dns_ratio": 0.12,
            "quic_ratio": 0.16,
            "unique_dst_ips": 44,
            "unique_dst_ports": 14,
            "total_flows": 120,
            "total_packets": 5000,
            "total_bytes": 1_000_000,
        },
    )

    assert result["device_class"] == "client_device"
    assert result["confidence"] >= 0.70


def test_phone_is_classified_as_client_device():
    result = classify_device({
        "ip": "192.168.1.21",
        "vendor": "Apple",
        "hostname": "iPhone",
        "open_ports": None,
    })

    assert result["device_class"] == "client_device"
    assert result["confidence"] >= 0.45


def test_router_gateway_is_classified_as_network_infrastructure():
    result = classify_device({
        "ip": "192.168.1.1",
        "vendor": "TP-Link",
        "hostname": "gateway-router",
        "open_ports": [
            {"port": 53, "service": "domain"},
            {"port": 80, "service": "http", "http_title": "TP-Link Router"},
            {"port": 1900, "service": "ssdp"},
        ],
    })

    assert result["device_class"] == "network_infrastructure"
    assert result["confidence"] >= 0.70


def test_infrastructure_service_ports_are_medium_confidence_infrastructure():
    result = classify_device({
        "ip": "192.168.1.2",
        "open_ports": [
            {"port": 53, "service": "dns"},
            {"port": 67, "service": "dhcp"},
            {"port": 68, "service": "dhcp"},
            {"port": 161, "service": "snmp"},
        ],
    })

    assert result["device_class"] == "network_infrastructure"
    assert result["confidence"] >= 0.45


def test_unknown_device_has_low_confidence_and_evidence():
    result = classify_device({"ip": "192.168.1.99"})

    assert result["device_class"] == "unknown"
    assert result["confidence"] <= 0.35
    assert result["evidence"]


def test_malformed_input_does_not_crash_and_returns_valid_class():
    samples = [
        {"open_ports": None},
        {"open_ports": "80, 443, invalid"},
        {"open_ports": [{"port": "bad"}, {"port": "1883", "service": "mqtt"}]},
        {"open_ports": {"port": "53", "service": "dns"}},
    ]

    for sample in samples:
        result = classify_device(sample, {"https_ratio": "bad", "total_flows": object()})
        assert result["device_class"] in DEVICE_CLASSES
        assert 0.0 <= result["confidence"] <= 1.0
        assert result["evidence"]


def test_build_device_features_parses_open_ports_safely():
    features = build_device_features(
        {"open_ports": "22, 443, 1883, not-a-port"},
        {"https_ratio": "0.5", "unique_dst_ips": "12"},
    )

    assert features["open_ports_set"] == {22, 443, 1883}
    assert features["has_22"] is True
    assert features["has_1883"] is True
    assert features["https_ratio"] == 0.5
    assert features["unique_dst_ips"] == 12


def test_build_device_features_clamps_ratios_and_counts():
    features = build_device_features(
        {"open_ports": [{"port": 443}]},
        {
            "https_ratio": 1.7,
            "dns_ratio": -0.2,
            "quic_ratio": "bad",
            "unique_dst_ips": -10,
            "total_flows": "15",
            "total_packets": "-50",
        },
    )

    assert features["https_ratio"] == 1.0
    assert features["dns_ratio"] == 0.0
    assert features["quic_ratio"] == 0.0
    assert features["unique_dst_ips"] == 0
    assert features["total_flows"] == 15
    assert features["total_packets"] == 0


def test_open_ports_list_of_ints_is_parsed():
    features = build_device_features({"open_ports": [80, "443", "bad", 1883]})

    assert features["open_ports_set"] == {80, 443, 1883}
    assert features["has_80"] is True
    assert features["has_443"] is True
    assert features["has_1883"] is True


def test_intel_vendor_without_hostname_or_flow_is_not_high_confidence_client():
    result = classify_device({"vendor": "Intel Corporate", "open_ports": []})

    assert result["device_class"] == "client_device"
    assert result["confidence"] < 0.70


def test_web_ports_alone_do_not_create_high_confidence_classification():
    result = classify_device({"open_ports": [{"port": 80}, {"port": 443}]})

    assert result["device_class"] == "unknown"
    assert result["confidence"] <= 0.35


def test_raspberry_pi_with_generic_ports_is_not_overconfident_iot():
    result = classify_device({
        "vendor": "Raspberry Pi",
        "open_ports": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}],
    })

    assert result["device_class"] == "iot_device"
    assert result["confidence"] < 0.70


def test_confidence_bounds_for_representative_devices():
    devices = [
        {"vendor": "Hikvision", "open_ports": [{"port": 554, "service": "rtsp"}]},
        {"vendor": "Microsoft", "hostname": "LAPTOP-123"},
        {"vendor": "MikroTik", "hostname": "gateway", "open_ports": [{"port": 53, "service": "dns"}]},
        {"ip": "192.168.1.10"},
    ]

    for device in devices:
        result = classify_device(device)
        assert 0.0 <= result["confidence"] <= 1.0
        assert result["device_class"] in DEVICE_CLASSES


def test_conflicting_evidence_lowers_confidence_and_reports_conflict():
    result = classify_device({
        "ip": "192.168.1.50",
        "vendor": "Intel Corporate",
        "hostname": "DESKTOP-MIXED",
        "open_ports": [
            {"port": 554, "service": "rtsp"},
            {"port": 1883, "service": "mqtt"},
        ],
    })

    assert result["device_class"] in {"iot_device", "client_device"}
    assert result["confidence"] < 0.85
    assert any("conflict" in item.lower() or "mixed" in item.lower() for item in result["evidence"])
