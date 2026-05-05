from fastapi import APIRouter, Depends, HTTPException

from sentinel_iot.api.dependencies import get_llm_analyst_service
from sentinel_iot.schemas.llm_schema import (
    CVEExplanationRequest,
    CVEExplanationResponse,
    DeviceAnalysisRequest,
    DeviceAnalysisResponse,
)
from sentinel_iot.services.llm_analyst_service import LLMAnalystService
from sentinel_iot.services.llm_context_service import CVEContextNotFoundError, DeviceContextNotFoundError
from sentinel_iot.services.llm_provider import ProviderConfigError, ProviderExecutionError, get_llm_provider_status_from_env

router = APIRouter(prefix="/llm", tags=["LLM"])


@router.get("/status")
def get_llm_status():
    """Return non-secret LLM capability/configuration status."""
    return get_llm_provider_status_from_env()


@router.post("/device-analysis", response_model=DeviceAnalysisResponse)
def analyze_device(
    payload: DeviceAnalysisRequest,
    service: LLMAnalystService = Depends(get_llm_analyst_service),
):
    """Generate grounded device analysis from persisted SentinelIoT context."""
    try:
        return service.analyze_device(payload)
    except DeviceContextNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ProviderConfigError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ProviderExecutionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/cve-explanation", response_model=CVEExplanationResponse)
def explain_cve(
    payload: CVEExplanationRequest,
    service: LLMAnalystService = Depends(get_llm_analyst_service),
):
    """Generate a grounded CVE explanation and next-step advice for a specific device service."""
    try:
        return service.explain_cve(payload)
    except (DeviceContextNotFoundError, CVEContextNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ProviderConfigError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ProviderExecutionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
