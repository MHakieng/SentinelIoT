"""Integration tests for the FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient

from sentinel_iot.api.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


class TestRootEndpoint:
    def test_root_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_root_has_app_name(self, client):
        data = client.get("/").json()
        assert data["app"] == "SentinelIoT API"

    def test_root_has_version(self, client):
        data = client.get("/").json()
        assert "version" in data


class TestDevicesEndpoint:
    def test_devices_returns_200(self, client):
        response = client.get("/devices")
        assert response.status_code == 200

    def test_devices_returns_list(self, client):
        data = client.get("/devices").json()
        assert isinstance(data, list)


class TestStatusEndpoint:
    def test_status_returns_200(self, client):
        response = client.get("/scanner/jobs")
        assert response.status_code == 200

    def test_status_has_status_field(self, client):
        data = client.get("/scanner/jobs").json()
        assert "status" in data


class TestMetricsEndpoint:
    def test_metrics_returns_200(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_has_scores(self, client):
        data = client.get("/metrics").json()
        metrics = data["synthetic_training_metrics"]
        assert "f1_score" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "average_precision" in metrics
        assert "validation_status" in metrics
        # Scores can be None if not validated yet, but keys must exist


class TestHistoryEndpoint:
    def test_history_returns_200(self, client):
        response = client.get("/monitor/history")
        assert response.status_code == 200

    def test_history_returns_list(self, client):
        data = client.get("/monitor/history").json()
        assert isinstance(data, list)


class TestLivePacketsEndpoint:
    def test_live_packets_returns_200(self, client):
        response = client.get("/monitor/packets")
        assert response.status_code == 200


class TestScanEndpoint:
    def test_scan_returns_200(self, client):
        # Mock the background scan to avoid triggering real nmap
        from unittest.mock import patch
        with patch("sentinel_iot.services.scanner_service.ScannerService.perform_full_scan"):
            response = client.post("/scanner/scans?target_range=192.168.1.0/24")
            assert response.status_code == 200
            assert "message" in response.json()
