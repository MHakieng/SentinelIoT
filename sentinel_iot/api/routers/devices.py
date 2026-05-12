from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sentinel_iot.schemas.device_schema import DeviceResult, DeviceHistory, AnomalyLogEntry
from sentinel_iot.services.risk_service import RiskService
from sentinel_iot.api.dependencies import get_risk_service
from sentinel_iot.database.db import get_all_devices, get_device_by_ip

router = APIRouter(prefix="/devices", tags=["Devices"])

@router.get("", response_model=List[DeviceResult])
def list_devices():
    """Return the persisted device inventory."""
    return get_all_devices()


@router.get("/{ip}", response_model=DeviceResult)
def get_device(ip: str):
    """Return a single persisted device by IP."""
    device = get_device_by_ip(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@router.get("/{ip}/history", response_model=List[DeviceHistory])
def get_device_history(ip: str, service: RiskService = Depends(get_risk_service)):
    """Retrieve historical risk scores for a specific device from DB."""
    return service.get_history(ip)

@router.get("/{ip}/anomalies", response_model=List[AnomalyLogEntry])
def get_device_anomalies(ip: str, service: RiskService = Depends(get_risk_service)):
    """Retrieve historical anomaly logs for a specific device from DB."""
    return service.get_anomalies(ip)


@router.get("/{ip}/risk")
def get_device_risk(ip: str, service: RiskService = Depends(get_risk_service)):
    """Compute and return contextual risk for a device (v6 contextual risk engine)."""
    device = get_device_by_ip(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return service.calculate_risk(ip)
