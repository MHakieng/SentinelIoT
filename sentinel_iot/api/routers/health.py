from fastapi import APIRouter

from sentinel_iot.database.db import init_db
from sentinel_iot.services.llm_provider import get_llm_provider_status_from_env

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Return a lightweight operational health summary."""
    database_status = "connected"
    try:
        init_db()
    except Exception:
        database_status = "unavailable"

    return {
        "status": "ok",
        "app": "SentinelIoT API",
        "database": {
            "database_status": database_status,
            "database_type": "sqlite",
            "path_exposed": False,
        },
        "llm": get_llm_provider_status_from_env(),
    }
