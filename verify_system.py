import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def check_endpoint(name, path, method="GET", params=None):
    print(f"[*] Testing {name} ({path})...", end=" ", flush=True)
    try:
        start = time.time()
        if method == "GET":
            r = requests.get(f"{BASE_URL}{path}", params=params, timeout=10)
        else:
            r = requests.post(f"{BASE_URL}{path}", params=params, timeout=10)
        
        duration = time.time() - start
        if r.status_code == 200:
            print(f"PASS ({duration:.2f}s)")
            return r.json()
        else:
            print(f"FAIL (Status: {r.status_code})")
            return None
    except Exception as e:
        print(f"ERROR ({e})")
        return None

def verify_all():
    print("--- Sentinel-IoT System Health Check ---")
    
    # 1. Basic Connectivity
    root = check_endpoint("Root API", "/")
    if not root: return
    
    # 2. Inventory Check
    devices = check_endpoint("Device Inventory", "/devices")
    
    # 3. ML Engine Check (The previous hanging one)
    metrics = check_endpoint("ML Metrics", "/metrics")
    
    # 4. Scanner Check
    print("\n[*] Testing Scanner (Triggering /scanner/scans on 127.0.0.1)...")
    scan_resp = check_endpoint("Scan Trigger", "/scanner/scans", method="POST", params={"target_range": "127.0.0.1/32"})
    
    if scan_resp and "job_id" in scan_resp:
        job_id = scan_resp["job_id"]
        # Poll status for 5 seconds
        for _ in range(3):
            time.sleep(2)
            check_endpoint(f"Job Status ({job_id})", f"/scanner/jobs/{job_id}")
            
    # 5. Monitoring Check
    print("\n[*] Testing Live Monitor...")
    check_endpoint("Monitor Start", "/monitor/live/start", method="POST", params={"duration": 1})
    time.sleep(2)
    check_endpoint("Live Packets", "/monitor/packets")
    check_endpoint("Live Flows", "/monitor/flows")
    check_endpoint("Monitor Stop", "/monitor/live/stop", method="POST")

    print("\n--- Health Check Finished ---")

if __name__ == "__main__":
    verify_all()
