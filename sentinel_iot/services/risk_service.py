from sentinel_iot.database.db import get_device_risk_history, get_device_anomaly_logs
from sentinel_iot.services.context_risk_engine import ContextualRiskEngine

class RiskService:
    """Service for managing risk score calculation and device history."""
    
    def __init__(self, risk_engine: ContextualRiskEngine):
        self.risk_engine = risk_engine

    def calculate_risk(self, asset_id: str):
        """Calculate contextual risk for a persisted asset (device ip)."""
        return self.risk_engine.calculate_risk(asset_id)

    def get_history(self, device_ip: str):
        """Retrieve historical risk scores."""
        return get_device_risk_history(device_ip)

    def get_anomalies(self, device_ip: str):
        """Retrieve historical anomaly logs."""
        return get_device_anomaly_logs(device_ip)
