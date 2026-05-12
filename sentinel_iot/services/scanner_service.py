import logging
import threading
import time
from typing import Any, Dict

from sentinel_iot.database.db import save_risk_history, save_scan_history, upsert_device
from sentinel_iot.scanner.network_scan import scan
from sentinel_iot.scanner.vulnerability_scan import scan_device
from sentinel_iot.services.context_risk_engine import ContextualRiskEngine
from sentinel_iot.services.job_manager import JobManager

logger = logging.getLogger(__name__)


class ScannerService:
    """Service for managing network discovery and vulnerability scans."""

    def __init__(self, risk_engine: ContextualRiskEngine, job_manager: JobManager):
        self.risk_engine = risk_engine
        self.job_manager = job_manager
        self.scan_lock = threading.Lock()
        self.scan_status = {
            "status": "idle",
            "active_job_id": None,
            "started_at": None,
            "updated_at": None,
            "message": "No scan has been started yet.",
            "error": None,
            "is_running": False,
            "last_event_at": None,
            "summary": {
                "devices_found": 0,
                "devices_scanned": 0,
                "failed_devices": 0,
            },
            "target": None,
            "profile": None,
            "last_completed_at": None,
        }

    @staticmethod
    def _timestamp() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _update_scan_status(self, **kwargs):
        now = self._timestamp()
        if any(key in kwargs for key in ("status", "message", "error", "summary")):
            kwargs.setdefault("last_event_at", now)
        kwargs.setdefault("updated_at", now)
        if "status" in kwargs:
            kwargs.setdefault("is_running", kwargs["status"] in {"pending", "running", "stopping"})
        self.scan_status.update(kwargs)

    def get_runtime_status(self) -> Dict[str, Any]:
        active_job = self.job_manager.get_active_job("scan")
        latest_job = self.job_manager.get_latest_job("scan")

        if active_job:
            return {
                "status": active_job.get("status", "running"),
                "active_job_id": active_job.get("id"),
                "started_at": active_job.get("started_at"),
                "updated_at": active_job.get("updated_at"),
                "message": active_job.get("message"),
                "error": active_job.get("error"),
                "is_running": active_job.get("is_running", True),
                "last_event_at": active_job.get("last_event_at"),
                "summary": active_job.get("summary") or self.scan_status.get("summary", {}),
                "target": active_job.get("target") or self.scan_status.get("target"),
                "profile": self.scan_status.get("profile"),
                "last_completed_at": self.scan_status.get("last_completed_at"),
            }

        if latest_job:
            return {
                "status": latest_job.get("status", self.scan_status.get("status", "idle")),
                "active_job_id": None,
                "started_at": latest_job.get("started_at"),
                "updated_at": latest_job.get("updated_at"),
                "message": latest_job.get("message") or self.scan_status.get("message"),
                "error": latest_job.get("error") or self.scan_status.get("error"),
                "is_running": False,
                "last_event_at": latest_job.get("last_event_at") or self.scan_status.get("last_event_at"),
                "summary": latest_job.get("summary") or self.scan_status.get("summary", {}),
                "target": latest_job.get("target") or self.scan_status.get("target"),
                "profile": self.scan_status.get("profile"),
                "last_completed_at": self.scan_status.get("last_completed_at"),
            }

        return dict(self.scan_status)

    def mark_scan_pending(self, job_id: str, target_range: str, profile: str):
        self._update_scan_status(
            status="pending",
            active_job_id=job_id,
            started_at=self._timestamp(),
            message=f"Scan queued for {target_range}.",
            error=None,
            is_running=True,
            target=target_range,
            profile=profile,
            summary={"devices_found": 0, "devices_scanned": 0, "failed_devices": 0},
        )

    def perform_full_scan(self, target_range: str, job_id: str, devices_db: Dict[str, Any], profile: str = "vulnerability"):
        """Background task to discover devices, scan services, calculate risk, and persist results."""
        with self.scan_lock:
            started_at = self._timestamp()
            initial_summary = {"devices_found": 0, "devices_scanned": 0, "failed_devices": 0}
            self._update_scan_status(
                status="running",
                active_job_id=job_id,
                started_at=started_at,
                message=f"Starting scan for {target_range}.",
                error=None,
                is_running=True,
                target=target_range,
                profile=profile,
                summary=initial_summary,
            )
            self.job_manager.update_job(
                job_id,
                status="running",
                progress=5,
                message=f"Starting scan for {target_range}.",
                summary=initial_summary,
            )

            failed_devices = []

            try:
                logger.info("Starting discovery on %s", target_range)
                found_devices = scan(target_range) or []
                total = len(found_devices)
                logger.info("Discovery finished on %s. Found %s devices.", target_range, total)

                discovery_summary = {"devices_found": total, "devices_scanned": 0, "failed_devices": 0}
                self._update_scan_status(message=f"Discovered {total} devices.", summary=discovery_summary)
                self.job_manager.update_job(job_id, progress=15, message=f"Discovered {total} devices.", summary=discovery_summary)

                for index, discovered_device in enumerate(found_devices):
                    ip = discovered_device.get("ip")
                    if not ip:
                        failed_devices.append({"ip": "unknown", "error": "Discovery result did not include an IP address."})
                        self._publish_scan_progress(job_id, index, total, failed_devices, "Skipped malformed discovery result.")
                        continue

                    logger.info("Scanning device %s (%s/%s) with profile '%s'", ip, index + 1, total, profile)
                    try:
                        scan_data = scan_device(ip, profile=profile) or []
                        # Persist device first so contextual engine can read latest open_ports / asset_type.
                        device_seed = {
                            "ip": ip,
                            "mac": discovered_device.get("mac", "Unknown"),
                            "vendor": discovered_device.get("vendor", "Unknown"),
                            "risk_score": 0.0,
                            "status": "Safe",
                            "open_ports": scan_data,
                            "total_cves": sum(len(p.get("cves") or []) for p in scan_data if isinstance(p, dict)),
                            "asset_type": "iot",
                            "priority": 1,
                            "risk_breakdown": {"vuln": 0.0, "anomaly": 0.0},
                        }
                        devices_db[ip] = device_seed
                        upsert_device(device_seed)

                        risk = self.risk_engine.calculate_risk(ip)

                        device_data = {
                            "ip": ip,
                            "mac": discovered_device.get("mac", "Unknown"),
                            "vendor": discovered_device.get("vendor", "Unknown"),
                            "risk_score": risk["risk_score"],
                            "status": risk["status"],
                            "open_ports": scan_data,
                            "total_cves": risk.get("total_cves", 0),
                            "asset_type": "iot",
                            "priority": 1,
                            "risk_breakdown": {
                                "vuln": risk.get("vuln_component", 0.0),
                                "anomaly": risk.get("anomaly_component", 0.0),
                            },
                        }

                        devices_db[ip] = device_data
                        upsert_ok = upsert_device(device_data)
                        risk_history_ok = save_risk_history(
                            ip,
                            device_data["risk_score"],
                            device_data["risk_breakdown"]["vuln"],
                            device_data["risk_breakdown"]["anomaly"],
                        )

                        if not upsert_ok or not risk_history_ok:
                            logger.warning("Persistence was partially unsuccessful for scanned device %s", ip)

                        self._publish_scan_progress(job_id, index, total, failed_devices, f"Scanned {index + 1}/{total} devices.")

                    except Exception as device_err:
                        failed_devices.append({"ip": ip, "error": str(device_err)})
                        self._publish_scan_progress(job_id, index, total, failed_devices, f"Scan failed for device {ip}.")
                        logger.error("Error scanning device %s: %s", ip, device_err, exc_info=True)

                self._finish_scan(job_id, found_devices, failed_devices)

            except Exception as exc:
                logger.error("Scan Service critical error: %s", exc, exc_info=True)
                runtime_summary = {
                    "devices_found": 0,
                    "devices_scanned": 0,
                    "failed_devices": len(failed_devices),
                }
                self.job_manager.finish_job(
                    job_id,
                    status="failed",
                    result={"devices_found": 0, "devices_scanned": 0, "failed_devices": failed_devices},
                    message="Scan failed.",
                    error=str(exc),
                    summary=runtime_summary,
                )
                self._update_scan_status(
                    status="failed",
                    active_job_id=None,
                    is_running=False,
                    message="Scan failed.",
                    error=str(exc),
                    summary=runtime_summary,
                    last_completed_at=self._timestamp(),
                )

    def _publish_scan_progress(self, job_id: str, index: int, total: int, failed_devices: list, message: str):
        summary = {
            "devices_found": total,
            "devices_scanned": index + 1 - len(failed_devices),
            "failed_devices": len(failed_devices),
        }
        progress = int(15 + (85 * (index + 1) / max(total, 1)))
        self._update_scan_status(message=message, error=None, summary=summary)
        self.job_manager.update_job(job_id, progress=progress, message=message, summary=summary)

    def _finish_scan(self, job_id: str, found_devices: list, failed_devices: list):
        total = len(found_devices)
        result_summary = {
            "devices_found": total,
            "devices_scanned": total - len(failed_devices),
            "failed_devices": failed_devices,
        }
        runtime_summary = {
            "devices_found": total,
            "devices_scanned": total - len(failed_devices),
            "failed_devices": len(failed_devices),
        }
        message = (
            f"Scan completed with {len(failed_devices)} device failures."
            if failed_devices
            else f"Scan completed successfully for {total} devices."
        )
        last_completed_at = self._timestamp()
        self._update_scan_status(
            status="completed",
            active_job_id=None,
            is_running=False,
            message=message,
            error=None,
            summary=runtime_summary,
            last_completed_at=last_completed_at,
        )
        save_scan_history(total, "full")
        self.job_manager.finish_job(job_id, result=result_summary, message=message, summary=runtime_summary)
