from fastapi import APIRouter, Depends
from typing import List, Dict, Any

from sentinel_iot.api.dependencies import get_monitor_service
from sentinel_iot.services.monitor_service import MonitorService


router = APIRouter(prefix="/traffic", tags=["Traffic"])


@router.get("/flows/scores", response_model=List[Dict[str, Any]])
def get_live_flow_scores(service: MonitorService = Depends(get_monitor_service)):
    """Return explainable runtime scores for the most recent live flows."""
    return service.get_live_flow_scores_snapshot()
