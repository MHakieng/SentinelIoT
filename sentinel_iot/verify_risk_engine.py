from sentinel_iot.core.risk_engine import RiskEngine

def test_new_risk_engine():
    engine = RiskEngine()
    
    print("--- Sentinel-IoT Risk Engine v6.0 Verification ---")
    
    # Scenario 1: Standard IoT Device, Medium Anomaly
    # Old logic: (0.5 * 100 * 0.4) = 20
    # New logic: (0.5 * 100 * 0.9 * 0.4) * 1.1 (IoT) = 19.8
    res1 = engine.calculate_device_risk(cvss_score=0, anomaly_score=0.5, asset_type='iot', anomaly_confidence=0.9)
    print(f"Scenario 1 (IoT, 0.5 Anom, 0.9 Conf): {res1}")

    # Scenario 2: Medical Device, Medium Anomaly
    # Same stats as above but on Medical equipment
    # New logic: (0.5 * 100 * 0.9 * 0.4) * 1.6 (Medical) = 28.8
    res2 = engine.calculate_device_risk(cvss_score=0, anomaly_score=0.5, asset_type='medical', anomaly_confidence=0.9)
    print(f"Scenario 2 (Medical, 0.5 Anom, 0.9 Conf): {res2}")

    # Scenario 3: Critical Vulnerability on Critical Infrastructure
    # Port 445 (SMB) has 1.7x multiplier in evaluate_device
    # Asset 'industrial' has 1.4x multiplier
    ports = [{"port": 445, "cves": [{"id": "CVE-TEST", "cvss": 7.0}]}]
    res3 = engine.evaluate_device(open_ports=ports, anomalies=[], asset_type='industrial')
    print(f"Scenario 3 (Industrial, SMB CVE 7.0): {res3['risk_score']} ({res3['status']})")

    # Scenario 4: High Anomaly but Low ML Confidence
    # Should result in a lower risk than high confidence
    res4_high = engine.calculate_device_risk(cvss_score=0, anomaly_score=0.8, asset_type='iot', anomaly_confidence=1.0)
    res4_low = engine.calculate_device_risk(cvss_score=0, anomaly_score=0.8, asset_type='iot', anomaly_confidence=0.3)
    print(f"Scenario 4 (High Conf): {res4_high['risk_score']} vs (Low Conf): {res4_low['risk_score']}")

if __name__ == "__main__":
    test_new_risk_engine()
