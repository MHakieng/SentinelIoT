"""Unit tests for SentinelIoT contextual risk scoring (v6)."""

import pytest

from sentinel_iot.services.context_risk_engine import ContextualRiskEngine


def make_engine():
    return ContextualRiskEngine()


class TestContextualRiskEngineProfile:
    """Profile anomaly scoring is deterministic and bounded."""

    def test_profile_anomaly_score_is_bounded(self):
        engine = make_engine()
        profile = engine._build_default_profiles()["iot"]
        observed = {80: "http", 23: "telnet", 1883: "mqtt"}
        score = engine._profile_anomaly_score(profile, observed)
        assert 0.0 <= score <= 100.0

    def test_profile_anomaly_score_increases_with_unexpected_ports(self):
        engine = make_engine()
        profile = engine._build_default_profiles()["iot"]
        baseline = engine._profile_anomaly_score(profile, {80: "http"})
        with_unexpected = engine._profile_anomaly_score(profile, {80: "http", 23: "telnet", 445: "smb"})
        assert with_unexpected > baseline

class TestContextualRiskEngineVulnerability:
    def test_vulnerability_score_increases_with_cvss(self):
        engine = make_engine()
        low_ports = [{"port": 80, "service": "http", "cves": [{"id": "CVE-X", "cvss": 3.1}]}]
        high_ports = [{"port": 80, "service": "http", "cves": [{"id": "CVE-X", "cvss": 9.8}]}]
        low, low_count = engine._vulnerability_score(low_ports)
        high, high_count = engine._vulnerability_score(high_ports)
        assert low_count == 1
        assert high_count == 1
        assert high > low
        assert 0.0 <= low <= 100.0
        assert 0.0 <= high <= 100.0
