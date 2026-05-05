import sys
import os
import time

# Add project root to path
sys.path.append(os.path.abspath(os.getcwd()))

from sentinel_iot.scanner.network_scan import scan
from sentinel_iot.scanner.vulnerability_scan import scan_device

def test_scan_bottleneck():
    target = "172.20.10.0/24"
    print(f"[*] Testing scan bottleneck for {target}...")
    
    start = time.time()
    try:
        print("[1] Starting discovery (nm.scan -sn -n)...")
        found = scan(target)
        print(f"[1] Finished. Found {len(found)} devices. Time: {time.time()-start:.2f}s")
        
        for i, d in enumerate(found):
            ip = d['ip']
            print(f"[2] Testing individual scan for {ip} (profile=quick)...")
            d_start = time.time()
            res = scan_device(ip, profile="quick")
            print(f"[2] Finished {ip}. Found {len(res)} ports. Time: {time.time()-d_start:.2f}s")
            
    except Exception as e:
        print(f"[-] ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_scan_bottleneck()
