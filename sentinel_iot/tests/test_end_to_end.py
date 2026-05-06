import threading

from fastapi.testclient import TestClient

from sentinel_iot.api.main import app
from sentinel_iot.core.risk_engine import RiskEngine
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.ml.generate_dataset import generate_iot_traffic


def test_full_pipeline_logic(tmp_path):
    """Validate the backend pipeline: traffic -> anomaly -> risk."""
    mock_scan_data = [
        {"port": 80, "service": "http", "version": "2.4.41", "cpe": "cpe:/a:apache:http_server:2.4.41"}
    ]

    flow_features = generate_iot_traffic(num_samples=1, anomaly_ratio=1.0)[0]

    model = AnomalyModel(model_path=str(tmp_path / "anomaly_model.joblib"))
    model.train(generate_iot_traffic(num_samples=200, anomaly_ratio=0.1))

    result = model.detect_anomaly(flow_features)
    assert "score" in result
    assert "label" in result

    risk_result = RiskEngine().evaluate_device(mock_scan_data, [result])

    assert "risk_score" in risk_result
    assert "status" in risk_result
    assert risk_result["anomaly_component"] > 0


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
