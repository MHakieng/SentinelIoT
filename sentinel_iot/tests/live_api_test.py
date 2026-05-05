import requests
import time
import json

BASE_URL = "http://127.0.0.1:8000"

def test_api_flow():
    print("--- Sentinel-IoT API Integration Test ---")
    
    # 1. Check Root
    print("\n[1] Testing / (Root)...")
    try:
        r = requests.get(f"{BASE_URL}/")
        assert r.status_code == 200
        print(f"    OK: {r.json()['version']}")
    except Exception as e:
        print(f"    FAILED: {e}")
        return

    # 2. Trigger Scan
    print("\n[2] Testing /scan (Trigger)...")
    try:
        # Scan local subnet (simulated or real)
        r = requests.post(f"{BASE_URL}/scan", params={"target_range": "127.0.0.1/32"})
        assert r.status_code == 200
        job_id = r.json()["job_id"]
        print(f"    OK: Job ID {job_id}")
    except Exception as e:
        print(f"    FAILED: {e}")
        return

    # 3. Check Job Status (Wait for completion)
    print("\n[3] Testing /status/{job_id}...")
    for _ in range(10):
        r = requests.get(f"{BASE_URL}/status/{job_id}")
        status = r.json().get("status")
        progress = r.json().get("progress")
        print(f"    - Status: {status} ({progress}%)")
        if status in ["completed", "failed"]:
            break
        time.sleep(2)

    # 4. Check Devices
    print("\n[4] Testing /devices...")
    r = requests.get(f"{BASE_URL}/devices")
    assert r.status_code == 200
    devices = r.json()
    print(f"    OK: Found {len(devices)} devices in inventory.")

    # 5. Check Metrics
    print("\n[5] Testing /metrics...")
    r = requests.get(f"{BASE_URL}/metrics")
    assert r.status_code == 200
    print(f"    OK: Metrics available (F1 Score: {r.json().get('synthetic_training_metrics', {}).get('f1_score')})")

    # 6. Start Monitor
    print("\n[6] Testing /test-live/start...")
    r = requests.post(f"{BASE_URL}/test-live/start", params={"duration": 2})
    assert r.status_code == 200
    monitor_job_id = r.json()["job_id"]
    print(f"    OK: Monitor Job ID {monitor_job_id}")

    # Wait for some packets/flows
    time.sleep(5)

    # 7. Check Live Data
    print("\n[7] Testing /live-packets & /live-flows...")
    pkts = requests.get(f"{BASE_URL}/live-packets").json()
    flows = requests.get(f"{BASE_URL}/live-flows").json()
    print(f"    OK: Captured {len(pkts)} packets and {len(flows)} flows so far.")

    # 8. Stop Monitor
    print("\n[8] Testing /test-live/stop...")
    r = requests.post(f"{BASE_URL}/test-live/stop")
    assert r.status_code == 200
    print("    OK: Stop signal sent.")

    print("\n--- ALL API TESTS COMPLETED ---")

if __name__ == "__main__":
    test_api_flow()
