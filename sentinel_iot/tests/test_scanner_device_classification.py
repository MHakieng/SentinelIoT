from fastapi.testclient import TestClient

from sentinel_iot.api.dependencies import get_devices_db
from sentinel_iot.api.main import app
from sentinel_iot.services.scanner_service import ScannerService


class FakeJobManager:
    def update_job(self, *args, **kwargs):
        return None

    def finish_job(self, *args, **kwargs):
        return None

    def get_active_job(self, *args, **kwargs):
        return None

    def get_latest_job(self, *args, **kwargs):
        return None


class FakeRiskEngine:
    def calculate_risk(self, asset_id):
        return {
            "risk_score": 12.0,
            "status": "Safe",
            "total_cves": 0,
            "vuln_component": 0.0,
            "anomaly_component": 0.0,
        }


def _run_scan(monkeypatch, discovered_device, open_ports):
    devices_db = {}
    service = ScannerService(FakeRiskEngine(), FakeJobManager())

    monkeypatch.setattr("sentinel_iot.services.scanner_service.scan", lambda _: [discovered_device])
    monkeypatch.setattr("sentinel_iot.services.scanner_service.scan_device", lambda ip, profile="vulnerability": open_ports)
    monkeypatch.setattr("sentinel_iot.services.scanner_service.upsert_device", lambda _: True)
    monkeypatch.setattr("sentinel_iot.services.scanner_service.save_risk_history", lambda *args, **kwargs: True)
    monkeypatch.setattr("sentinel_iot.services.scanner_service.save_scan_history", lambda *args, **kwargs: True)

    service.perform_full_scan("192.168.1.0/24", "job-1", devices_db)
    return devices_db


def test_scanner_result_adds_device_classification_metadata(monkeypatch):
    devices_db = _run_scan(
        monkeypatch,
        {
            "ip": "192.168.1.30",
            "mac": "00:11:22:33:44:55",
            "vendor": "Hikvision",
            "hostname": "IPCAM",
            "discovery_sources": ["arp", "hostname"],
        },
        [
            {"port": 80, "service": "http", "http_title": "Hikvision IP Camera"},
            {"port": 554, "service": "rtsp", "product": "camera stream"},
        ],
    )

    device = devices_db["192.168.1.30"]
    assert device["device_class"] == "iot_device"
    assert "device_class_confidence" in device
    assert isinstance(device["device_class_evidence"], list)
    assert device["device_class_evidence"]
    assert device["device_class_method"] == "rule_based"


def test_scanner_unknown_fallback_metadata(monkeypatch):
    devices_db = _run_scan(
        monkeypatch,
        {
            "ip": "192.168.1.99",
            "mac": "Unknown",
            "vendor": "Unknown",
            "hostname": "",
            "discovery_sources": [],
        },
        [],
    )

    device = devices_db["192.168.1.99"]
    assert device["device_class"] == "unknown"
    assert device["device_class_confidence"] <= 0.35
    assert device["device_class_method"] == "rule_based"


def test_classifier_exception_does_not_fail_scanner(monkeypatch):
    devices_db = {}
    service = ScannerService(FakeRiskEngine(), FakeJobManager())

    monkeypatch.setattr(
        "sentinel_iot.services.scanner_service.scan",
        lambda _: [{"ip": "192.168.1.40", "mac": "Unknown", "vendor": "Unknown"}],
    )
    monkeypatch.setattr("sentinel_iot.services.scanner_service.scan_device", lambda ip, profile="vulnerability": [])
    monkeypatch.setattr("sentinel_iot.services.scanner_service.upsert_device", lambda _: True)
    monkeypatch.setattr("sentinel_iot.services.scanner_service.save_risk_history", lambda *args, **kwargs: True)
    monkeypatch.setattr("sentinel_iot.services.scanner_service.save_scan_history", lambda *args, **kwargs: True)

    def fail_classifier(_device):
        raise RuntimeError("classifier unavailable")

    monkeypatch.setattr("sentinel_iot.services.scanner_service.classify_device", fail_classifier)

    service.perform_full_scan("192.168.1.0/24", "job-1", devices_db)

    device = devices_db["192.168.1.40"]
    assert device["device_class"] == "unknown"
    assert device["device_class_confidence"] == 0.0
    assert "fallback" in " ".join(device["device_class_evidence"]).lower()


def test_asset_type_legacy_value_is_preserved(monkeypatch):
    devices_db = _run_scan(
        monkeypatch,
        {"ip": "192.168.1.31", "mac": "Unknown", "vendor": "Espressif IoT Node"},
        [{"port": 1883, "service": "mqtt"}],
    )

    assert devices_db["192.168.1.31"]["asset_type"] == "iot"


def test_devices_response_keeps_legacy_fields_and_enriches_optional_metadata(monkeypatch):
    db_devices = [{
        "ip": "192.168.1.30",
        "mac": "00:11:22:33:44:55",
        "vendor": "Hikvision",
        "risk_score": 12.0,
        "status": "Safe",
        "open_ports": [],
        "total_cves": 0,
        "asset_type": "iot",
        "priority": 1,
        "risk_breakdown": {"vuln": 0.0, "anomaly": 0.0},
    }]
    memory_devices = {
        "192.168.1.30": {
            "device_class": "iot_device",
            "device_class_confidence": 0.9,
            "device_class_evidence": ["IoT-specific port(s) observed: 554"],
            "device_class_method": "rule_based",
        }
    }

    monkeypatch.setattr("sentinel_iot.api.routers.devices.get_all_devices", lambda: db_devices)
    app.dependency_overrides[get_devices_db] = lambda: memory_devices
    try:
        response = TestClient(app).get("/devices")
    finally:
        app.dependency_overrides.pop(get_devices_db, None)

    assert response.status_code == 200
    [device] = response.json()
    for field in (
        "ip",
        "mac",
        "vendor",
        "status",
        "risk_score",
        "open_ports",
        "total_cves",
        "asset_type",
        "priority",
        "risk_breakdown",
    ):
        assert field in device
    assert device["device_class"] == "iot_device"
    assert device["device_class_method"] == "rule_based"


def test_devices_response_without_metadata_remains_legacy_shape(monkeypatch):
    db_devices = [{
        "ip": "192.168.1.50",
        "mac": "Unknown",
        "vendor": "Unknown",
        "risk_score": 0.0,
        "status": "Safe",
        "open_ports": [],
        "total_cves": 0,
        "asset_type": "iot",
        "priority": 1,
        "risk_breakdown": {"vuln": 0.0, "anomaly": 0.0},
    }]

    monkeypatch.setattr("sentinel_iot.api.routers.devices.get_all_devices", lambda: db_devices)
    app.dependency_overrides[get_devices_db] = lambda: {}
    try:
        response = TestClient(app).get("/devices")
    finally:
        app.dependency_overrides.pop(get_devices_db, None)

    assert response.status_code == 200
    [device] = response.json()
    assert "device_class" not in device
    assert device["asset_type"] == "iot"


def test_single_device_response_enriches_optional_metadata(monkeypatch):
    db_device = {
        "ip": "192.168.1.60",
        "mac": "00:AA:BB:CC:DD:EE",
        "vendor": "TP-Link",
        "risk_score": 18.0,
        "status": "Safe",
        "open_ports": [{"port": 53, "service": "dns"}],
        "total_cves": 0,
        "asset_type": "iot",
        "priority": 1,
        "risk_breakdown": {"vuln": 0.0, "anomaly": 0.0},
    }
    memory_devices = {
        "192.168.1.60": {
            "device_class": "network_infrastructure",
            "device_class_confidence": 0.8,
            "device_class_evidence": ["Infrastructure service port(s) observed: 53"],
            "device_class_method": "rule_based",
        }
    }

    monkeypatch.setattr("sentinel_iot.api.routers.devices.get_device_by_ip", lambda ip: db_device if ip == "192.168.1.60" else None)
    app.dependency_overrides[get_devices_db] = lambda: memory_devices
    try:
        response = TestClient(app).get("/devices/192.168.1.60")
    finally:
        app.dependency_overrides.pop(get_devices_db, None)

    assert response.status_code == 200
    device = response.json()
    assert device["ip"] == "192.168.1.60"
    assert device["asset_type"] == "iot"
    assert device["device_class"] == "network_infrastructure"
    assert device["device_class_method"] == "rule_based"


def test_openapi_documents_optional_device_class_fields():
    response = TestClient(app).get("/openapi.json")

    assert response.status_code == 200
    schemas = response.json()["components"]["schemas"]
    properties = schemas["DeviceResult"]["properties"]
    for field in (
        "device_class",
        "device_class_confidence",
        "device_class_evidence",
        "device_class_method",
    ):
        assert field in properties
