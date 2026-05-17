from sentinel_iot.ml.device_class_scoring import apply_device_class_context
from sentinel_iot.ml.flow_scorer import score_flow


def _base_score(flow, anomaly_score):
    return score_flow(flow, ml_raw_score=anomaly_score, ml_anomaly_score=anomaly_score)


def test_client_device_https_burst_is_not_promoted_to_anomaly():
    flow = {
        "flow_id": "client-https",
        "src_ip": "192.168.1.10",
        "dst_ip": "93.184.216.34",
        "dst_port": 443,
        "protocol": 6,
        "packet_count": 120,
        "byte_count": 80_000,
        "duration": 2.0,
        "mean_iat": 0.03,
        "var_iat": 0.002,
        "packet_rate": 60,
    }
    base = _base_score(flow, 0.55)
    result = apply_device_class_context(base, flow, source_device_class="client_device")

    assert result["final_flow_risk"] < base["final_flow_risk"]
    assert result["decision"] != "anomaly"
    assert "Client device common web/DNS traffic context" in result["class_aware_reasons"]


def test_inbound_https_response_to_client_is_not_promoted_to_anomaly():
    flow = {
        "flow_id": "google-response",
        "src_ip": "172.217.171.74",
        "dst_ip": "10.116.62.68",
        "src_port": 443,
        "dst_port": 49324,
        "protocol": 6,
        "packet_count": 90,
        "byte_count": 120_000,
        "duration": 2.0,
        "mean_iat": 0.03,
        "var_iat": 0.002,
        "packet_rate": 45,
    }
    base = _base_score(flow, 0.76)
    result = apply_device_class_context(base, flow, destination_device_class="client_device")

    assert result["final_flow_risk"] < base["final_flow_risk"]
    assert result["decision"] != "anomaly"
    assert "Client device common web/DNS traffic context" in result["class_aware_reasons"]


def test_client_device_dns_and_quic_receive_context_reward():
    dns_flow = {"dst_port": 53, "protocol": 17, "packet_rate": 20, "mean_iat": 0.05, "var_iat": 0.01}
    quic_flow = {"dst_port": 443, "protocol": 17, "packet_rate": 30, "mean_iat": 0.04, "var_iat": 0.01}

    dns = apply_device_class_context(_base_score(dns_flow, 0.40), dns_flow, source_device_class="client_device")
    quic = apply_device_class_context(_base_score(quic_flow, 0.40), quic_flow, source_device_class="client_device")

    assert dns["class_aware_adjustment"] < 0
    assert quic["class_aware_adjustment"] < dns["class_aware_adjustment"]
    assert dns["decision"] != "anomaly"
    assert quic["decision"] != "anomaly"


def test_iot_device_telnet_burst_remains_anomaly():
    flow = {
        "dst_port": 23,
        "protocol": 6,
        "packet_rate": 300,
        "byte_count": 2_000_000,
        "duration": 1.0,
        "mean_iat": 0.005,
        "var_iat": 0.2,
    }
    result = apply_device_class_context(_base_score(flow, 0.92), flow, source_device_class="iot_device")

    assert result["decision"] == "anomaly"
    assert result["severity"] == "critical"
    assert result["class_aware_adjustment"] > 0


def test_iot_device_mqtt_telemetry_gets_expected_service_context():
    flow = {"dst_port": 1883, "protocol": 6, "packet_rate": 3, "mean_iat": 0.5, "var_iat": 0.0005}
    base = _base_score(flow, 0.25)
    result = apply_device_class_context(base, flow, source_device_class="iot_device")

    assert result["final_flow_risk"] <= base["final_flow_risk"]
    assert result["decision"] != "anomaly"
    assert "IoT device expected service traffic context" in result["class_aware_reasons"]


def test_network_infrastructure_dns_service_is_not_anomaly_by_itself():
    flow = {"dst_port": 53, "protocol": 17, "packet_rate": 150, "mean_iat": 0.03, "var_iat": 0.01}
    result = apply_device_class_context(_base_score(flow, 0.50), flow, source_device_class="network_infrastructure")

    assert result["class_aware_adjustment"] < 0
    assert result["decision"] != "anomaly"


def test_unknown_context_is_safe_and_conservative():
    flow = {"dst_port": 443, "protocol": 6, "packet_rate": 10}
    result = apply_device_class_context(_base_score(flow, 0.35), flow)

    assert result["source_device_class"] == "unknown"
    assert result["destination_device_class"] == "unknown"
    assert result["class_aware_adjustment"] == 0.0
    assert "Unknown device context; conservative scoring applied" in result["class_aware_reasons"]


def test_base_scoring_fields_are_preserved():
    flow = {"flow_id": "preserve", "dst_port": 443, "protocol": 6, "packet_rate": 2}
    base = _base_score(flow, 0.12)
    result = apply_device_class_context(base, flow, source_device_class="client_device")

    for field in ("flow_id", "ml_anomaly_score", "reward_points", "penalty_points", "features"):
        assert field in result
    assert result["flow_id"] == base["flow_id"]
