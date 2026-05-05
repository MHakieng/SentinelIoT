import sys
import os

# Add sentinel_iot directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("Testing Sentinel-IoT Imports...")

try:
    print("1. Testing core.risk_engine...")
    from core.risk_engine import RiskEngine
    print("   [OK]")
    
    print("2. Testing ml.anomaly_model...")
    from ml.anomaly_model import AnomalyModel
    print("   [OK]")
    
    print("3. Testing database.db...")
    from database.db import init_db, get_all_devices
    print("   [OK]")

    print("4. Testing Services...")
    from services.job_manager import JobManager
    from services.scanner_service import ScannerService
    from services.monitor_service import MonitorService
    from services.ml_service import MLService
    from services.risk_service import RiskService
    print("   [OK]")

    print("5. Testing Dependencies...")
    from api import dependencies
    print("   [OK]")

    print("6. Testing Routers...")
    from api.routers import devices, scanner, monitor, ml
    print("   [OK]")

    print("7. Testing api.main (App Init)...")
    from api.main import app
    print("   [OK]")

    print("--- ALL IMPORTS SUCCESSFUL ---")
except Exception as e:
    print(f"--- IMPORT FAILED ---")
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
