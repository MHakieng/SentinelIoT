from fastapi import APIRouter, HTTPException
from typing import Dict, Optional
from sentinel_iot.database.db import get_setting, set_setting
from pydantic import BaseModel

router = APIRouter(prefix="/api/settings", tags=["settings"])

class SettingsUpdate(BaseModel):
    port_modifiers: Optional[Dict[str, float]] = None
    asset_multipliers: Optional[Dict[str, float]] = None

@router.get("/risk-weights")
def get_risk_weights():
    return {
        "port_modifiers": get_setting("port_modifiers", {
            "21": 1.5, "22": 1.6, "23": 1.7, "445": 1.7, "3389": 1.6, "1883": 1.2, "502": 1.4
        }),
        "asset_multipliers": get_setting("asset_multipliers", {
            "medical": 1.6, "industrial": 1.4, "iot": 1.1, "home": 1.0, "guest": 0.8
        })
    }

@router.put("/risk-weights")
def update_risk_weights(settings: SettingsUpdate):
    if settings.port_modifiers is not None:
        if not set_setting("port_modifiers", settings.port_modifiers):
            raise HTTPException(status_code=500, detail="Could not save port_modifiers")
    if settings.asset_multipliers is not None:
        if not set_setting("asset_multipliers", settings.asset_multipliers):
            raise HTTPException(status_code=500, detail="Could not save asset_multipliers")
    return {"status": "success", "message": "Risk weights updated successfully"}
