"""Unit tests for SentinelIoT risk scoring."""

import pytest

from sentinel_iot.core.risk_engine import RiskEngine


def make_engine():
    return RiskEngine()


class TestRiskFormula:
    """Direct formula tests for weighted fusion and input validation."""

    def test_weighted_fusion_low(self):
        result = make_engine().calculate_device_risk(2.0, 0.1)
        assert result["risk_score"] == 17.6
        assert result["status"] == "Safe"
        assert result["vuln_component"] == 20.0
        assert result["anomaly_component"] == 10.0

    def test_weighted_fusion_medium_boundary_with_iot_multiplier(self):
        result = make_engine().calculate_device_risk(5.0, 0.5)
        assert result["risk_score"] == 55.0
        assert result["status"] == "High Risk"

    def test_weighted_fusion_high_is_capped_by_critical_threshold(self):
        result = make_engine().calculate_device_risk(8.0, 0.9)
        assert result["risk_score"] == 92.4
        assert result["status"] == "Critical Risk"

    def test_validation_errors(self):
        engine = make_engine()
        with pytest.raises(ValueError, match="gecersiz"):
            engine.calculate_device_risk(11.0, 0.5)
        with pytest.raises(ValueError, match="gecersiz"):
            engine.calculate_device_risk(5.0, 1.5)
        with pytest.raises(ValueError, match="gecersiz"):
            engine.calculate_device_risk(5.0, 0.5, anomaly_confidence=1.5)


class TestSafeDevice:
    """A device with no ports and no anomalies should be safe."""

    def test_score_is_zero(self):
        result = make_engine().evaluate_device([], [])
        assert result["risk_score"] == 0.0

    def test_status_is_safe(self):
        result = make_engine().evaluate_device([], [])
        assert result["status"] == "Safe"

    def test_no_cves(self):
        result = make_engine().evaluate_device([], [])
        assert result["total_cves"] == 0


class TestPortOnlyScoring:
    """Devices with open ports but no CVEs and no anomalies."""

    def test_single_non_critical_port(self):
        ports = [{"port": 80, "service": "http", "cves": []}]
        result = make_engine().evaluate_device(ports, [])
        assert result["risk_score"] == 3.3
        assert result["vuln_component"] == 5.0
        assert result["status"] == "Safe"

    def test_critical_port_increases_score(self):
        ports = [{"port": 23, "service": "telnet", "cves": []}]
        result = make_engine().evaluate_device(ports, [])
        assert result["risk_score"] == 14.52
        assert result["vuln_component"] == 22.0

    def test_multiple_ports_include_port_modifiers(self):
        ports = [
            {"port": 80, "service": "http", "cves": []},
            {"port": 443, "service": "https", "cves": []},
            {"port": 1883, "service": "mqtt", "cves": []},
        ]
        result = make_engine().evaluate_device(ports, [])
        assert result["risk_score"] == 17.82
        assert result["vuln_component"] == 27.0


class TestCVEScoring:
    """Devices with CVEs trigger contextual confidence scoring."""

    def test_cve_triggers_contextual_scoring(self):
        ports = [{"port": 80, "service": "http", "cves": ["CVE-2021-1234"]}]
        result = make_engine().evaluate_device(ports, [])
        assert result["total_cves"] == 1
        assert result["max_contextual_score"] == 2.45
        assert result["status"] == "Safe"

    def test_cve_with_anomaly_correlation(self):
        ports = [{"port": 22, "service": "ssh", "cves": ["CVE-1", "CVE-2"]}]
        anomalies = [{"score": 0.8}]
        result = make_engine().evaluate_device(ports, anomalies)
        assert result["risk_score"] > 50
        assert result["status"] == "High Risk"
        assert result["raw_anomaly_score"] == 0.8
        assert result["anomaly_component"] == 64.0

    def test_real_cvss_score_usage(self):
        ports = [{"port": 80, "service": "http", "cves": [{"id": "CVE-X", "cvss": 9.8}]}]
        result = make_engine().evaluate_device(ports, [])
        assert result["risk_score"] > 15.0
        assert result["max_contextual_score"] > 3.0


class TestAnomalyOnlyScoring:
    """Devices with anomalies but no CVEs."""

    def test_high_anomaly_score(self):
        result = make_engine().evaluate_device([], [{"score": 0.9}])
        assert result["risk_score"] == 31.68
        assert result["status"] == "Medium Risk"

    def test_low_anomaly_stays_safe(self):
        result = make_engine().evaluate_device([], [{"score": 0.1}])
        assert result["risk_score"] == 3.52
        assert result["status"] == "Safe"

    def test_multiple_anomalies_takes_max(self):
        anomalies = [{"score": 0.3}, {"score": 0.7}, {"score": 0.5}]
        result = make_engine().evaluate_device([], anomalies)
        assert result["raw_anomaly_score"] == 0.7
        assert result["anomaly_component"] == 56.0


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_score_capped_at_100(self):
        ports = [
            {"port": 22, "service": "ssh", "cves": [f"CVE-{i}" for i in range(20)]},
            {"port": 23, "service": "telnet", "cves": [f"CVE-{i}" for i in range(20)]},
            {"port": 445, "service": "smb", "cves": [f"CVE-{i}" for i in range(20)]},
        ]
        result = make_engine().evaluate_device(ports, [{"score": 1.0}])
        assert result["risk_score"] <= 100.0

    def test_invalid_anomaly_in_evaluate_device_raises(self):
        with pytest.raises(ValueError, match="gecersiz"):
            make_engine().evaluate_device([], [{"score": 60.0}])
