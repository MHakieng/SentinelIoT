from fastapi.testclient import TestClient

from sentinel_iot.api.dependencies import get_monitor_service
from sentinel_iot.api.main import app
from sentinel_iot.ml.device_class_scoring import score_flow_with_device_context
from sentinel_iot.ml.flow_scorer import score_flow, score_flows


def test_normal_https_flow_is_low_with_reward():
    result = score_flow(
        {
            "flow_id": "a:1->b:443 [6]",
            "src_ip": "192.168.1.10",
            "dst_ip": "93.184.216.34",
            "src_port": 50000,
            "dst_port": 443,
            "protocol": 6,
            "packet_count": 5,
            "byte_count": 2500,
            "duration": 2.0,
            "avg_packet_size": 500,
            "mean_iat": 0.5,
            "var_iat": 0.0005,
            "packet_rate": 2.5,
            "bytes_per_second": 1250,
        },
        ml_raw_score=0.08,
        ml_anomaly_score=0.08,
    )

    assert result["severity"] == "low"
    assert result["reward_points"] > 0
    assert result["final_flow_risk"] < 35


def test_telnet_burst_flow_is_critical_with_telnet_reason():
    result = score_flow(
        {
            "flow_id": "a:1->b:23 [6]",
            "src_ip": "192.168.1.20",
            "dst_ip": "192.168.1.30",
            "src_port": 51000,
            "dst_port": 23,
            "protocol": 6,
            "packet_count": 400,
            "byte_count": 2_500_000,
            "duration": 1.0,
            "avg_packet_size": 6250,
            "mean_iat": 0.005,
            "var_iat": 0.2,
            "packet_rate": 400,
            "bytes_per_second": 2_500_000,
        },
        ml_raw_score=0.92,
        ml_anomaly_score=0.92,
    )

    assert result["severity"] == "critical"
    assert result["penalty_points"] >= 70
    assert any("Telnet" in reason or "insecure access" in reason for reason in result["reasons"])


def test_flow_risk_clamps_to_100_and_0():
    high = score_flow(
        {"dst_port": 23, "packet_rate": 500, "mean_iat": 0.001, "byte_count": 5_000_000, "duration": 1},
        ml_raw_score=1.0,
        ml_anomaly_score=1.0,
    )
    low = score_flow(
        {"dst_port": 443, "packet_rate": 1, "mean_iat": 0.5, "var_iat": 0.0001},
        ml_raw_score=0.0,
        ml_anomaly_score=0.0,
    )

    assert high["final_flow_risk"] == 100.0
    assert low["final_flow_risk"] == 0.0


def test_missing_fields_do_not_crash():
    result = score_flow({}, ml_raw_score=0.1, ml_anomaly_score=0.1)

    assert result["flow_id"] == ""
    assert result["severity"] == "low"
    assert isinstance(result["reasons"], list)


def test_non_finite_values_do_not_escape_score_bounds():
    result = score_flow(
        {
            "packet_count": "nan",
            "byte_count": float("inf"),
            "duration": "-inf",
            "mean_iat": "nan",
            "var_iat": "nan",
            "dst_port": float("inf"),
        },
        ml_raw_score=float("nan"),
        ml_anomaly_score=float("nan"),
    )

    assert 0.0 <= result["final_flow_risk"] <= 100.0
    assert result["ml_anomaly_score"] == 0.0
    assert result["severity"] == "low"


def test_nested_feature_payload_is_scored_consistently():
    result = score_flow(
        {
            "flow_id": "nested-flow",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20",
            "dst_port": 23,
            "protocol": "TCP",
            "features": {
                "packet_count": 250,
                "byte_count": 1_500_000,
                "duration": 1.0,
                "avg_packet_size": 6000,
                "mean_iat": 0.005,
                "var_iat": 0.02,
                "packets_per_second": 250,
            },
        },
        ml_raw_score=0.85,
        ml_anomaly_score=0.85,
    )

    assert result["features"]["packet_count"] == 250
    assert result["features"]["packets_per_second"] == 250
    assert result["penalty_points"] >= 70
    assert result["severity"] == "critical"


def test_score_flows_uses_attack_probability_fallback():
    [result] = score_flows([
        {
            "flow_id": "rf-flow",
            "dst_port": 443,
            "packet_rate": 4,
            "mean_iat": 0.4,
            "var_iat": 0.0001,
            "attack_probability": 0.91,
        }
    ])

    assert result["ml_anomaly_score"] == 0.91
    assert result["severity"] == "critical"


def test_monitor_adds_device_class_context_from_devices_db():
    service = get_monitor_service()
    flow = {"src_ip": "192.168.1.10", "dst_ip": "192.168.1.1"}
    contextual = service._flow_with_device_context(
        flow,
        {
            "192.168.1.10": {"device_class": "client_device", "device_class_confidence": 0.72},
            "192.168.1.1": {"device_class": "network_infrastructure", "device_class_confidence": 0.86},
        },
    )

    assert contextual["source_device_class"] == "client_device"
    assert contextual["source_device_class_confidence"] == 0.72
    assert contextual["destination_device_class"] == "network_infrastructure"
    assert contextual["destination_device_class_confidence"] == 0.86


def test_live_flow_scores_endpoint_returns_scoring_fields():
    service = get_monitor_service()
    flow_id = "192.168.1.10:50000->192.168.1.20:443 [6]"
    with service._lock:
        original_flows = dict(service.live_flows)
        service.live_flows = {
            flow_id: {
                "flow_id": flow_id,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": 6,
                "packet_count": 3,
                "byte_count": 1500,
                "duration": 1.0,
                "avg_packet_size": 500,
                "mean_iat": 0.5,
                "var_iat": 0.0001,
                "packet_rate": 3,
                "anomaly_score": 0.05,
                "source_device_class": "client_device",
            }
        }

    try:
        response = TestClient(app).get("/traffic/flows/scores")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert data
        assert "final_flow_risk" in data[0]
        assert "severity" in data[0]
        assert "reasons" in data[0]
        assert data[0]["source_device_class"] == "client_device"
        assert "class_aware_adjustment" in data[0]
        assert "decision" in data[0]
    finally:
        with service._lock:
            service.live_flows = original_flows


def test_live_flow_scores_endpoint_returns_empty_list_without_live_flows():
    service = get_monitor_service()
    with service._lock:
        original_flows = dict(service.live_flows)
        service.live_flows = {}

    try:
        response = TestClient(app).get("/traffic/flows/scores")
        assert response.status_code == 200
        assert response.json() == []
    finally:
        with service._lock:
            service.live_flows = original_flows


def test_live_flow_scores_endpoint_handles_malformed_scores():
    service = get_monitor_service()
    flow_id = "192.168.1.10:50000->192.168.1.20:80 [6]"
    with service._lock:
        original_flows = dict(service.live_flows)
        service.live_flows = {
            flow_id: {
                "flow_id": flow_id,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "src_port": 50000,
                "dst_port": 80,
                "protocol": 6,
                "packet_count": "nan",
                "byte_count": "bad",
                "duration": "bad",
                "avg_packet_size": None,
                "mean_iat": "nan",
                "var_iat": "nan",
                "packet_rate": "bad",
                "anomaly_score": "bad",
            }
        }

    try:
        response = TestClient(app).get("/traffic/flows/scores")
        assert response.status_code == 200
        data = response.json()
        assert data[0]["final_flow_risk"] == 0.0
        assert data[0]["severity"] == "low"
    finally:
        with service._lock:
            service.live_flows = original_flows


def test_score_flow_with_device_context_preserves_base_fields():
    result = score_flow_with_device_context(
        {
            "flow_id": "ctx-flow",
            "src_ip": "192.168.1.10",
            "dst_ip": "93.184.216.34",
            "src_port": 50100,
            "dst_port": 443,
            "protocol": 6,
            "packet_count": 4,
            "byte_count": 2400,
            "duration": 1.0,
            "avg_packet_size": 600,
            "mean_iat": 0.3,
            "var_iat": 0.0005,
            "source_device_class": "client_device",
        },
        ml_raw_score=0.1,
        ml_anomaly_score=0.1,
    )

    assert result["flow_id"] == "ctx-flow"
    assert result["source_device_class"] == "client_device"
    assert result["class_aware_adjustment"] < 0
    assert result["decision"] in {"normal", "suspicious", "anomaly"}


def test_monitor_uses_persisted_device_class_context_for_live_flows(monkeypatch):
    service = get_monitor_service()

    monkeypatch.setattr(
        "sentinel_iot.services.monitor_service.get_all_devices",
        lambda: [
            {
                "ip": "10.116.62.68",
                "mac": "Unknown",
                "vendor": "Unknown",
                "open_ports": [
                    {"port": 135, "service": "msrpc", "product": "Microsoft Windows RPC"},
                    {"port": 445, "service": "microsoft-ds", "product": "Microsoft Windows SMB"},
                ],
            }
        ],
    )

    context = service._build_device_context_db({})

    assert context["10.116.62.68"]["device_class"] == "client_device"


def test_monitor_does_not_persist_calibrated_non_anomaly(monkeypatch):
    service = get_monitor_service()
    flow_id = "172.217.171.74:443->10.116.62.68:49324 [6]"
    features = [{
        "flow_id": flow_id,
        "src_ip": "172.217.171.74",
        "dst_ip": "10.116.62.68",
        "src_port": 443,
        "dst_port": 49324,
        "protocol": 6,
        "packet_count": 90,
        "byte_count": 120_000,
        "duration": 2.0,
        "avg_packet_size": 1333.33,
        "mean_iat": 0.03,
        "var_iat": 0.002,
        "packet_rate": 45,
    }]

    monkeypatch.setattr(
        "sentinel_iot.services.monitor_service.get_all_devices",
        lambda: [{"ip": "10.116.62.68", "vendor": "Unknown", "open_ports": [{"port": 135, "product": "Microsoft Windows RPC"}]}],
    )
    monkeypatch.setattr(
        service.anomaly_model,
        "detect_anomaly",
        lambda flow: {"label": "anomaly", "score": 0.76, "raw_score": 0.76, "confidence": 0.76},
    )

    with service._lock:
        original_flows = dict(service.live_flows)
        service.live_flows = {flow_id: dict(features[0])}

    try:
        anomalies = service._score_features_and_collect_anomalies(features, devices_db={})
        assert anomalies == []
        with service._lock:
            scored = service.live_flows[flow_id]
            assert scored["destination_device_class"] == "client_device"
            assert scored["decision"] != "anomaly"
            assert scored["label"] == 0
    finally:
        with service._lock:
            service.live_flows = original_flows
