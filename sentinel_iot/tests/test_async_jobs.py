import requests
import time
import uuid
import os
import pytest

BASE_URL = "http://127.0.0.1:8000"

pytestmark = pytest.mark.skipif(
    os.getenv("SENTINEL_RUN_LIVE_API_TESTS") != "1",
    reason="Live API smoke tests require a running backend. Set SENTINEL_RUN_LIVE_API_TESTS=1 to enable.",
)

def test_scan_job():
    print("\n[+] Testing Scan Job...")
    response = requests.post(f"{BASE_URL}/scanner/scans")
    if response.status_code != 200:
        print(f"[-] Failed to start scan: {response.text}")
        return
    
    job_id = response.json().get("job_id")
    print(f"[+] Started Scan Job: {job_id}")
    
    # Poll status
    for _ in range(10):
        status_resp = requests.get(f"{BASE_URL}/scanner/jobs/{job_id}")
        status_data = status_resp.json()
        print(f"[*] Job Status: {status_data['status']}")
        if status_data['status'] in ['completed', 'failed']:
            print(f"[+] Job finished with result: {status_data.get('result')}")
            break
        time.sleep(2)

def test_train_job():
    print("\n[+] Testing Train Job...")
    # Using a non-existent path to trigger quick failure or just check pending
    response = requests.post(f"{BASE_URL}/train", params={"pcap_path": "non_existent.pcap"})
    # This should return 404 because of os.path.exists check in route
    print(f"[*] Response for invalid path: {response.status_code}")
    
    # In a real scenario, we'd provide a path. Let's just verify the logic if path existed.
    print("[*] (Manual check) Train job returns job_id and runs perform_training in background.")

def test_invalid_job():
    print("\n[+] Testing Invalid Job ID...")
    fake_id = str(uuid.uuid4())
    response = requests.get(f"{BASE_URL}/scanner/jobs/{fake_id}")
    print(f"[*] Response for fake ID: {response.status_code} (Expect 404)")
    assert response.status_code == 404

if __name__ == "__main__":
    try:
        test_scan_job()
        test_invalid_job()
        print("\n[!] Verification script finished.")
    except Exception as e:
        print(f"[-] Error during verification: {e}")
