from sentinel_iot.services.context_risk_engine import ContextualRiskEngine
from sentinel_iot.database.db import upsert_device, save_risk_history

def test_new_risk_engine():
    engine = ContextualRiskEngine()
    
    print("--- Sentinel-IoT Contextual Risk Engine Verification ---")
    
    # Scenario 1: IoT device with expected HTTP and a CVE
    ip = "192.168.1.10"
    upsert_device(
        {
            "ip": ip,
            "mac": "00:00:00:00:00:00",
            "vendor": "Test",
            "risk_score": 0.0,
            "status": "Safe",
            "open_ports": [{"port": 80, "service": "http", "cves": [{"id": "CVE-TEST", "cvss": 7.0}]}],
            "total_cves": 1,
            "asset_type": "iot",
            "priority": 1,
            "risk_breakdown": {"vuln": 0.0, "anomaly": 0.0},
        }
    )
    save_risk_history(ip, 10.0, 5.0, 5.0)
    res1 = engine.calculate_risk(ip)
    print(f"Scenario 1 (IoT, HTTP + CVE): {res1}")

    # Scenario 2: Industrial asset type weights anomaly more (uses same stored state)
    ip2 = "192.168.1.11"
    upsert_device(
        {
            "ip": ip2,
            "mac": "00:00:00:00:00:01",
            "vendor": "Test",
            "risk_score": 0.0,
            "status": "Safe",
            "open_ports": [{"port": 502, "service": "modbus", "cves": []}],
            "total_cves": 0,
            "asset_type": "industrial",
            "priority": 1,
            "risk_breakdown": {"vuln": 0.0, "anomaly": 0.0},
        }
    )
    save_risk_history(ip2, 10.0, 5.0, 5.0)
    res2 = engine.calculate_risk(ip2)
    print(f"Scenario 2 (Industrial, Modbus): {res2}")

if __name__ == "__main__":
    test_new_risk_engine()
