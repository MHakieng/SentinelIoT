from typing import List, Dict, Any, Optional
from sentinel_iot.core.risk_engine import RiskEngine
from sentinel_iot.database.db import get_device_risk_history, get_device_anomaly_logs

class RiskService:
    """Service for managing risk score calculation and device history."""
    
    def __init__(self, risk_engine: RiskEngine):
        self.risk_engine = risk_engine

    def calculate_risk(self, open_ports: List[Dict[str, Any]], anomalies: List[Dict[str, Any]], asset_type='iot'):
        """Calculate context-aware risk score."""
        return self.risk_engine.evaluate_device(open_ports, anomalies, asset_type=asset_type)

    def get_history(self, device_ip: str):
        """Retrieve historical risk scores."""
        return get_device_risk_history(device_ip)

    def get_anomalies(self, device_ip: str):
        """Retrieve historical anomaly logs."""
        return get_device_anomaly_logs(device_ip)
