import threading

from fastapi.testclient import TestClient

from sentinel_iot.api.main import app
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.ml.generate_dataset import generate_iot_traffic
from sentinel_iot.services.context_risk_engine import ContextualRiskEngine
from sentinel_iot.database.db import upsert_device, save_anomaly_log, save_risk_history


def test_full_pipeline_logic(tmp_path):
    """Validate the backend pipeline: traffic -> anomaly -> contextual risk."""
    device_ip = "192.168.1.50"
    mock_scan_data = [{"port": 80, "service": "http", "cves": [{"id": "CVE-X", "cvss": 7.5}]}]

    flow_features = generate_iot_traffic(num_samples=1, anomaly_ratio=1.0)[0]

    model = AnomalyModel(model_path=str(tmp_path / "anomaly_model.joblib"))
    model.train(generate_iot_traffic(num_samples=200, anomaly_ratio=0.1))

    result = model.detect_anomaly(flow_features)
    assert "score" in result
    assert "label" in result

    # Persist a minimal device snapshot + anomaly evidence so ContextualRiskEngine can read DB state.
    upsert_device(
        {
            "ip": device_ip,
            "mac": "00:00:00:00:00:00",
            "vendor": "Test",
            "risk_score": 0.0,
            "status": "Safe",
            "open_ports": mock_scan_data,
            "total_cves": 1,
            "asset_type": "iot",
            "priority": 1,
            "risk_breakdown": {"vuln": 0.0, "anomaly": 0.0},
        }
    )
    save_anomaly_log(device_ip, "test_anomaly", float(result.get("score", 0.0)), {"score": float(result.get("score", 0.0))})
    save_risk_history(device_ip, 10.0, 5.0, 5.0)

    risk_result = ContextualRiskEngine().calculate_risk(device_ip)

    assert "risk_score" in risk_result
    assert "status" in risk_result
    assert risk_result["anomaly_component"] >= 0
    assert 0.0 <= risk_result["risk_score"] <= 100.0


def test_api_concurrency_stress():
    """Send simultaneous in-process API requests and verify state remains stable."""
    results = []
    errors = []
    client = TestClient(app)

    def make_request():
        try:
            resp1 = client.get("/devices")
            resp2 = client.get("/scanner/jobs")
            results.append(resp1.status_code)
            results.append(resp2.status_code)
        except Exception as exc:
            errors.append(str(exc))

    threads = []
    for _ in range(10):
        thread = threading.Thread(target=make_request)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert errors == []
    assert all(status == 200 for status in results)
    assert len(results) == 20
