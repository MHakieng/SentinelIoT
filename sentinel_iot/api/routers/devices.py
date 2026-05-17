from fastapi import APIRouter, Depends, HTTPException
from typing import Any, Dict, List
from sentinel_iot.schemas.device_schema import DeviceHistory, AnomalyLogEntry, DeviceResult
from sentinel_iot.services.risk_service import RiskService
from sentinel_iot.api.dependencies import get_devices_db, get_risk_service
from sentinel_iot.database.db import get_all_devices, get_device_by_ip

router = APIRouter(prefix="/devices", tags=["Devices"])

DEVICE_CLASS_METADATA_FIELDS = (
    "device_class",
    "device_class_confidence",
    "device_class_evidence",
    "device_class_method",
)


def _enrich_with_device_class_metadata(device: Dict[str, Any], devices_db: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(device)
    metadata_source = devices_db.get(device.get("ip"), {}) if isinstance(devices_db, dict) else {}
    for field in DEVICE_CLASS_METADATA_FIELDS:
        if field in metadata_source:
            enriched[field] = metadata_source[field]
    return enriched


@router.get("", response_model=List[DeviceResult], response_model_exclude_none=True)
def list_devices(devices_db: Dict[str, Any] = Depends(get_devices_db)):
    """Return the persisted device inventory."""
    return [_enrich_with_device_class_metadata(device, devices_db) for device in get_all_devices()]


@router.get("/{ip}", response_model=DeviceResult, response_model_exclude_none=True)
def get_device(ip: str, devices_db: Dict[str, Any] = Depends(get_devices_db)):
    """Return a single persisted device by IP."""
    device = get_device_by_ip(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _enrich_with_device_class_metadata(device, devices_db)

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
