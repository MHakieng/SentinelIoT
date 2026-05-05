import threading
import time
from typing import Dict, Any, Optional


class JobManager:
    """Centralized service for managing asynchronous job states."""
    
    def __init__(self):
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _timestamp() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def create_job(self, job_id: str, job_type: str, target: Optional[str] = None):
        timestamp = self._timestamp()
        with self._lock:
            self._jobs[job_id] = {
                "id": job_id,
                "type": job_type,
                "status": "pending",
                "started_at": timestamp,
                "updated_at": timestamp,
                "start_time": timestamp,
                "progress": 0,
                "target": target,
                "result": None,
                "message": None,
                "error": None,
                "active_job_id": job_id,
                "is_running": False,
                "last_event_at": timestamp,
                "summary": None,
            }
        return self._jobs[job_id]

    def update_job(self, job_id: str, **kwargs):
        with self._lock:
            if job_id in self._jobs:
                now = self._timestamp()
                kwargs.setdefault("updated_at", now)
                if any(key in kwargs for key in ("status", "message", "error", "result", "progress", "summary")):
                    kwargs.setdefault("last_event_at", now)
                if "status" in kwargs:
                    kwargs.setdefault("is_running", kwargs["status"] in {"pending", "running", "stopping"})
                if "active_job_id" not in kwargs:
                    current_status = kwargs.get("status", self._jobs[job_id].get("status"))
                    kwargs["active_job_id"] = job_id if current_status in {"pending", "running", "stopping"} else None
                self._jobs[job_id].update(kwargs)
                return self._jobs[job_id]
        return None

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return self._jobs.copy()

    def get_latest_job(self, job_type: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            jobs = [job for job in self._jobs.values() if job.get("type") == job_type]
            if not jobs:
                return None
            return max(jobs, key=lambda job: job.get("updated_at") or job.get("started_at") or "")

    def get_active_job(self, job_type: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for job in self._jobs.values():
                if job.get("type") == job_type and job.get("status") in {"pending", "running", "stopping"}:
                    return job
        return None

    def finish_job(self, job_id: str, result: Any, status: str = "completed", message: Optional[str] = None, error: Optional[str] = None, summary: Optional[Dict[str, Any]] = None):
        payload = {
            "status": status,
            "result": result,
            "progress": 100,
            "is_running": False,
            "active_job_id": None,
        }
        if message is not None:
            payload["message"] = message
        if error is not None:
            payload["error"] = error
        if summary is not None:
            payload["summary"] = summary
        self.update_job(job_id, **payload)
