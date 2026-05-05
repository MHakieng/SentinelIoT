from fastapi import APIRouter

from sentinel_iot.database.db import DB_PATH
from sentinel_iot.services.llm_provider import get_llm_provider_status_from_env

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Return a lightweight operational health summary."""
    return {
        "status": "ok",
        "app": "SentinelIoT API",
        "database": {
            "type": "sqlite",
            "path": DB_PATH,
        },
        "llm": get_llm_provider_status_from_env(),
    }
