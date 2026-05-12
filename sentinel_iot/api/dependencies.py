from typing import Dict, Any, List
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.services.job_manager import JobManager
from sentinel_iot.services.scanner_service import ScannerService
from sentinel_iot.services.monitor_service import MonitorService
from sentinel_iot.services.ml_service import MLService
from sentinel_iot.services.risk_service import RiskService
from sentinel_iot.services.context_risk_engine import ContextualRiskEngine
from sentinel_iot.services.llm_provider import build_llm_provider_from_env, UnavailableLLMProvider, ProviderConfigError
from sentinel_iot.services.llm_context_service import LLMContextService
from sentinel_iot.services.llm_analyst_service import LLMAnalystService

# Singleton Engine Instances
context_risk_engine = ContextualRiskEngine()
anomaly_model = AnomalyModel()

# Shared In-Memory Data Store (Thread-safe inside services)
# In a bigger app, this could be Redis.
DEVICES_DB = {} 

# Service Instances (Singletons)
job_manager = JobManager()
scanner_service = ScannerService(context_risk_engine, job_manager)
monitor_service = MonitorService(context_risk_engine, anomaly_model, job_manager)
ml_service = MLService(anomaly_model, job_manager)
risk_service = RiskService(context_risk_engine)
llm_provider = build_llm_provider_from_env
llm_context_service = LLMContextService(monitor_service)

def get_job_manager() -> JobManager:
    return job_manager

def get_scanner_service() -> ScannerService:
    return scanner_service

def get_monitor_service() -> MonitorService:
    return monitor_service

def get_ml_service() -> MLService:
    return ml_service

def get_risk_service() -> RiskService:
    return risk_service

def get_llm_provider():
    try:
        return llm_provider()
    except ProviderConfigError as exc:
        return UnavailableLLMProvider(str(exc))

def get_llm_context_service() -> LLMContextService:
    return llm_context_service

def get_llm_analyst_service() -> LLMAnalystService:
    return LLMAnalystService(get_llm_provider(), get_llm_context_service())

def get_devices_db() -> Dict[str, Any]:
    return DEVICES_DB
