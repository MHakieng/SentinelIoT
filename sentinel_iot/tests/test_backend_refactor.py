import sys
import os
import pytest
from fastapi.testclient import TestClient

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_iot.api.main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Refactored" in response.json()["version"]

def test_list_devices():
    response = client.get("/devices")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_status():
    response = client.get("/scanner/jobs")
    assert response.status_code == 200
    assert "status" in response.json()

def test_get_metrics():
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "real_world_metrics" not in data
    assert data["runtime_detection_metrics"] is None
    assert data["runtime_metrics_metadata"]["source"] == "not_available"

if __name__ == "__main__":
    pytest.main([__file__])
