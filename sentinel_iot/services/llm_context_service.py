from typing import Any, Dict, List, Optional

from sentinel_iot.database.db import (
    get_device_anomaly_logs,
    get_device_by_ip,
    get_device_risk_history,
)
from sentinel_iot.services.monitor_service import MonitorService


class DeviceContextNotFoundError(ValueError):
    """Raised when the requested device does not exist."""


class CVEContextNotFoundError(ValueError):
    """Raised when the requested CVE could not be found on the device."""


class LLMContextService:
    def __init__(self, monitor_service: MonitorService):
        self.monitor_service = monitor_service

    def build_device_analysis_context(self, device_ip: str, history_limit: int = 8, anomaly_limit: int = 8) -> Dict[str, Any]:
        device = get_device_by_ip(device_ip)
        if not device:
            raise DeviceContextNotFoundError(f"Device '{device_ip}' was not found.")

        risk_history = get_device_risk_history(device_ip)
        anomaly_logs = get_device_anomaly_logs(device_ip)
        runtime_status = self.monitor_service.get_runtime_status()

        recent_history = risk_history[-history_limit:]
        recent_anomalies = anomaly_logs[:anomaly_limit]
        open_ports = device.get("open_ports") or []
        risk_breakdown = device.get("risk_breakdown") or {}

        warnings: List[str] = []
        if not open_ports:
            warnings.append("No service fingerprint data is stored for this device.")
        if not recent_history:
            warnings.append("No risk history is stored for this device yet.")
        if not recent_anomalies:
            warnings.append("No recent anomaly records were found for this device.")
        if runtime_status.get("status") in {None, "evaluation_unavailable"}:
            warnings.append("Live monitor runtime state is unavailable and should not be treated as real-time evidence.")

        open_service_snapshot = [
            {
                "port": port.get("port"),
                "service": port.get("service"),
                "product": port.get("product") or None,
                "version": port.get("version") or None,
                "http_title": port.get("http_title") or None,
                "banner": (str(port.get("banner", ""))[:160] or None) if port.get("banner") else None,
                "cve_count": len(port.get("cves") or []),
            }
            for port in open_ports[:6]
        ]

        anomaly_snapshot = [
            {
                "timestamp": log.get("timestamp"),
                "type": log.get("type"),
                "score": log.get("score"),
            }
            for log in recent_anomalies[:5]
        ]

        summary = {
            "risk_score": float(device.get("risk_score", 0.0)),
            "status": device.get("status", "Unknown"),
            "vuln_component": float(risk_breakdown.get("vuln", 0.0)),
            "anomaly_component": float(risk_breakdown.get("anomaly", 0.0)),
            "total_cves": int(device.get("total_cves", 0)),
            "open_service_count": len(open_ports),
            "recent_anomaly_count": len(recent_anomalies),
            "risk_history_points": len(recent_history),
            "latest_risk_timestamp": recent_history[-1]["timestamp"] if recent_history else None,
            "latest_anomaly_timestamp": recent_anomalies[0]["timestamp"] if recent_anomalies else None,
            "monitor_runtime_status": runtime_status.get("status"),
        }

        return {
            "device": device,
            "risk_history": recent_history,
            "anomaly_logs": recent_anomalies,
            "monitor_runtime_status": {
                "status": runtime_status.get("status"),
                "message": runtime_status.get("message"),
                "last_event_at": runtime_status.get("last_event_at"),
            },
            "grounding_summary": summary,
            "evidence_used": self._build_evidence(device, recent_history, recent_anomalies),
            "warnings": warnings,
            "open_service_snapshot": open_service_snapshot,
            "anomaly_snapshot": anomaly_snapshot,
        }

    def build_cve_explanation_context(
        self,
        device_ip: str,
        cve_id: str,
        port: int | None = None,
        service: str | None = None,
        anomaly_limit: int = 5,
    ) -> Dict[str, Any]:
        device = get_device_by_ip(device_ip)
        if not device:
            raise DeviceContextNotFoundError(f"Device '{device_ip}' was not found.")

        open_ports = device.get("open_ports") or []
        matches = []
        normalized_cve_id = cve_id.strip().upper()
        normalized_service = service.strip().lower() if service else None

        for port_info in open_ports:
            cve_context = self._extract_cve_context_from_port(port_info, normalized_cve_id)
            if not cve_context.get("matched"):
                continue
            if port is not None and int(port_info.get("port", -1)) != int(port):
                continue
            if normalized_service and str(port_info.get("service", "")).lower() != normalized_service:
                continue
            matches.append((port_info, cve_context))

        if not matches:
            raise CVEContextNotFoundError(
                f"CVE '{normalized_cve_id}' was not found in the stored scan context for device '{device_ip}'."
            )

        selected_port, selected_cve_context = matches[0]
        anomaly_logs = get_device_anomaly_logs(device_ip)[:anomaly_limit]
        risk_breakdown = device.get("risk_breakdown") or {}

        warnings: List[str] = []
        if len(matches) > 1:
            warnings.append("This CVE appears on more than one stored service. The explanation uses the first matching service.")
        if selected_cve_context.get("match_source") == "scripts_only":
            warnings.append("This CVE was matched from raw scan script data rather than the normalized CVE list.")
        if not selected_port.get("product") and not selected_port.get("banner") and not selected_port.get("http_title"):
            warnings.append("Detailed service fingerprint data is limited for this CVE context.")
        if selected_cve_context.get("cvss_score") is None:
            warnings.append("No CVSS score is stored for this CVE in the scan context.")
        if not selected_cve_context.get("local_description"):
            warnings.append("No local vulnerability description is stored for this CVE in the scan context.")
        warnings.append("Patch suitability and exploit certainty must not be inferred unless they are present in scan evidence.")

        grounding_summary = {
            "device_ip": device_ip,
            "risk_score": float(device.get("risk_score", 0.0)),
            "device_status": device.get("status", "Unknown"),
            "cve_id": normalized_cve_id,
            "port": selected_port.get("port"),
            "service": selected_port.get("service"),
            "service_product": selected_port.get("product") or None,
            "service_version": selected_port.get("version") or None,
            "service_http_title": selected_port.get("http_title") or None,
            "cvss_score": selected_cve_context.get("cvss_score"),
            "local_description": selected_cve_context.get("local_description"),
            "total_cves_on_device": int(device.get("total_cves", 0)),
            "matched_service_cve_count": len(selected_port.get("cves") or []),
            "vuln_component": float(risk_breakdown.get("vuln", 0.0)),
            "anomaly_component": float(risk_breakdown.get("anomaly", 0.0)),
            "recent_anomaly_count": len(anomaly_logs),
        }

        evidence = [
            {
                "source": "device_inventory",
                "detail": f"Device risk score is {device.get('risk_score', 0)} and status is {device.get('status', 'Unknown')}.",
            },
            {
                "source": "service_exposure",
                "detail": f"{normalized_cve_id} is associated with port {selected_port.get('port')} ({selected_port.get('service', 'unknown service')}).",
            },
        ]

        if selected_port.get("product") or selected_port.get("version") or selected_port.get("extrainfo"):
            fingerprint = " ".join(
                str(value)
                for value in [
                    selected_port.get("product"),
                    selected_port.get("version"),
                    selected_port.get("extrainfo"),
                ]
                if value
            )
            evidence.append({"source": "service_fingerprint", "detail": f"Service fingerprint: {fingerprint}"})
        if selected_cve_context.get("cvss_score") is not None:
            evidence.append({"source": "cve_score", "detail": f"Stored CVSS score for {normalized_cve_id} is {selected_cve_context['cvss_score']}."})
        if selected_cve_context.get("local_description"):
            evidence.append({"source": "cve_description", "detail": selected_cve_context["local_description"]})
        if selected_port.get("reason"):
            evidence.append({"source": "scan_reason", "detail": f"Detection reason: {selected_port.get('reason')}."})
        if anomaly_logs:
            evidence.append({"source": "anomaly_logs", "detail": f"{len(anomaly_logs)} recent anomaly records exist for this device."})

        return {
            "device": device,
            "selected_port": selected_port,
            "selected_cve_context": selected_cve_context,
            "anomaly_logs": anomaly_logs,
            "grounding_summary": grounding_summary,
            "evidence_used": evidence,
            "warnings": warnings,
            "service_snapshot": {
                "port": selected_port.get("port"),
                "service": selected_port.get("service"),
                "product": selected_port.get("product") or None,
                "version": selected_port.get("version") or None,
                "extrainfo": selected_port.get("extrainfo") or None,
                "http_title": selected_port.get("http_title") or None,
                "banner": (str(selected_port.get("banner", ""))[:160] or None) if selected_port.get("banner") else None,
            },
        }

    def _extract_cve_context_from_port(self, port_info: Dict[str, Any], normalized_cve_id: str) -> Dict[str, Any]:
        matched = False
        cvss_score: Optional[float] = None
        local_description: Optional[str] = None
        match_source = "none"

        for entry in port_info.get("cves") or []:
            normalized = self._normalize_cve_entry(entry)
            if normalized.get("id") != normalized_cve_id:
                continue
            matched = True
            cvss_score = normalized.get("cvss_score")
            local_description = normalized.get("description")
            match_source = "normalized_cve_list"
            break

        script_context = self._extract_cve_details_from_scripts(port_info.get("scripts") or {}, normalized_cve_id)
        matched = matched or script_context.get("matched", False)
        if cvss_score is None:
            cvss_score = script_context.get("cvss_score")
        if not local_description:
            local_description = script_context.get("local_description")
        if match_source == "none" and script_context.get("matched"):
            match_source = "scripts_only"
        elif match_source != "none" and script_context.get("matched"):
            match_source = "normalized_and_scripts"

        return {
            "matched": matched,
            "cvss_score": cvss_score,
            "local_description": local_description,
            "match_source": match_source,
        }

    def _normalize_cve_entry(self, entry: Any) -> Dict[str, Any]:
        if isinstance(entry, str):
            return {"id": entry.strip().upper(), "cvss_score": None, "description": None}

        if isinstance(entry, dict):
            cve_id = entry.get("id") or entry.get("cve") or entry.get("cve_id") or entry.get("name") or ""
            return {
                "id": str(cve_id).strip().upper(),
                "cvss_score": self._coerce_score(
                    entry.get("cvss")
                    or entry.get("cvss_score")
                    or entry.get("cvss_base")
                    or entry.get("score")
                ),
                "description": self._clean_text(
                    entry.get("description")
                    or entry.get("summary")
                    or entry.get("title")
                ),
            }

        return {"id": str(entry).strip().upper(), "cvss_score": None, "description": None}

    def _extract_cve_details_from_scripts(self, scripts: Dict[str, Any], normalized_cve_id: str) -> Dict[str, Any]:
        for script_name, payload in scripts.items():
            details = self._search_nested_cve_payload(payload, normalized_cve_id)
            if details.get("matched"):
                details.setdefault("source", script_name)
                return details
        return {"matched": False, "cvss_score": None, "local_description": None}

    def _search_nested_cve_payload(self, payload: Any, normalized_cve_id: str) -> Dict[str, Any]:
        if isinstance(payload, dict):
            normalized_entry = self._normalize_cve_entry(payload)
            if normalized_entry.get("id") == normalized_cve_id:
                return {
                    "matched": True,
                    "cvss_score": normalized_entry.get("cvss_score"),
                    "local_description": normalized_entry.get("description"),
                }

            for key, value in payload.items():
                if str(key).strip().upper() == normalized_cve_id:
                    return self._extract_cve_value_payload(value)

                nested = self._search_nested_cve_payload(value, normalized_cve_id)
                if nested.get("matched"):
                    return nested

        if isinstance(payload, list):
            for item in payload:
                nested = self._search_nested_cve_payload(item, normalized_cve_id)
                if nested.get("matched"):
                    return nested

        if isinstance(payload, str) and normalized_cve_id in payload.upper():
            return {
                "matched": True,
                "cvss_score": None,
                "local_description": self._clean_text(payload),
            }

        return {"matched": False, "cvss_score": None, "local_description": None}

    def _extract_cve_value_payload(self, value: Any) -> Dict[str, Any]:
        description = None
        cvss_score = None
        if isinstance(value, dict):
            description = self._clean_text(value.get("description") or value.get("summary") or value.get("title"))
            cvss_score = self._coerce_score(
                value.get("cvss")
                or value.get("cvss_score")
                or value.get("cvss_base")
                or value.get("score")
            )
        elif isinstance(value, str):
            description = self._clean_text(value)

        return {
            "matched": True,
            "cvss_score": cvss_score,
            "local_description": description,
        }

    def _coerce_score(self, value: Any) -> Optional[float]:
        try:
            if value is None or value == "":
                return None
            return round(float(value), 1)
        except (TypeError, ValueError):
            return None

    def _clean_text(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = " ".join(str(value).split())
        return text[:600] if text else None

    def _build_evidence(self, device: Dict[str, Any], risk_history: List[Dict[str, Any]], anomaly_logs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        evidence: List[Dict[str, str]] = [
            {
                "source": "device_inventory",
                "detail": f"Risk score is {device.get('risk_score', 0)} with status {device.get('status', 'Unknown')}.",
            },
            {
                "source": "device_inventory",
                "detail": f"Device has {len(device.get('open_ports') or [])} recorded services and {device.get('total_cves', 0)} total CVEs.",
            },
        ]

        risk_breakdown = device.get("risk_breakdown") or {}
        evidence.append(
            {
                "source": "risk_breakdown",
                "detail": f"Exposure component is {risk_breakdown.get('vuln', 0)} and monitoring component is {risk_breakdown.get('anomaly', 0)}.",
            }
        )

        if risk_history:
            evidence.append(
                {
                    "source": "risk_history",
                    "detail": f"Latest recorded risk history point is {risk_history[-1]['timestamp']}.",
                }
            )

        if anomaly_logs:
            latest = anomaly_logs[0]
            evidence.append(
                {
                    "source": "anomaly_logs",
                    "detail": (
                        f"Most recent anomaly log is '{latest.get('type', 'Unknown')}' at {latest.get('timestamp')} "
                        f"with score {latest.get('score', 0)}."
                    ),
                }
            )

        return evidence
