from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sentinel_iot.database.db import SessionLocal
from sentinel_iot.database.models import AnomalyLog, Device, RiskHistory, utc_now


@dataclass(frozen=True)
class AssetProfile:
    """Expected service surface for an asset type.

    Notes:
    - This is a prototype-grade, heuristic baseline. It is NOT a ground-truth
      fingerprinting system and should be presented as such.
    """

    name: str
    expected_services: Dict[int, List[str]]  # port -> list of acceptable service names


class ContextualRiskEngine:
    """Context-aware risk engine that fuses:
    - profile anomaly (expected vs observed service surface)
    - vulnerability evidence (CVE list + optional CVSS-like scores)
    - runtime anomaly evidence (last 1h)
    - trend multiplier (increasing/decreasing/stable with spike boost)

    Contract:
    - Returns a 0-100 float risk score.
    - Does NOT claim runtime TP/FP/F1; this is a scoring engine only.
    """

    DEFAULT_CVSS_FALLBACK = 7.0

    def __init__(self):
        self._profiles = self._build_default_profiles()

    # -------------------------
    # Public API
    # -------------------------
    def calculate_risk(self, asset_id: str) -> Dict[str, Any]:
        """Calculate contextual risk for a persisted asset (device ip)."""
        device = self._get_device(asset_id)
        if not device:
            raise ValueError(f"Asset '{asset_id}' not found.")

        asset_type = (device.asset_type or "iot").strip().lower()
        profile = self._profiles.get(asset_type, self._profiles["iot"])

        open_ports = device.open_ports or []
        observed = self._extract_observed_services(open_ports)

        profile_score = self._profile_anomaly_score(profile, observed)
        vuln_score, total_cves = self._vulnerability_score(open_ports)
        anomaly_score = self._runtime_anomaly_score_last_hour(asset_id)

        weights = self._weights_for_asset_type(asset_type)
        base_score = (
            profile_score * weights["profile"]
            + vuln_score * weights["vulnerability"]
            + anomaly_score * weights["anomaly"]
        )

        trend = self._risk_trend(asset_id)
        spike_multiplier = self._spike_multiplier(asset_id, trend)
        normalized = float(max(0.0, min(100.0, base_score * spike_multiplier)))

        status = self._status_label(normalized)

        return {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "profile": profile.name,
            "risk_score": round(normalized, 2),
            "status": status,
            # Keep legacy-compatible breakdown keys used by UI/DB history writers.
            "vuln_component": round(float(vuln_score), 2),
            "anomaly_component": round(float(anomaly_score), 2),
            # Additional context for explainability/debugging.
            "profile_anomaly_score": round(float(profile_score), 2),
            "total_cves": int(total_cves),
            "weights": weights,
            "trend": trend,
            "spike_multiplier": round(float(spike_multiplier), 3),
            "observed_service_count": len(observed),
        }

    # -------------------------
    # Profiles
    # -------------------------
    @staticmethod
    def _build_default_profiles() -> Dict[str, AssetProfile]:
        """Prototype profiles keyed by asset_type.

        asset_type values are stored on Device rows (default: iot).
        """

        # Camera / DVR-like profile: common web + RTSP.
        ip_camera = AssetProfile(
            name="IP Kamera",
            expected_services={
                80: ["http"],
                443: ["https"],
                554: ["rtsp"],
                8000: ["http"],
                8080: ["http", "http-proxy"],
            },
        )

        # PLC / industrial profile: Modbus/TCP, sometimes HTTP for management.
        plc = AssetProfile(
            name="PLC",
            expected_services={
                502: ["modbus", "modbus-tcp"],
                80: ["http"],
                443: ["https"],
            },
        )

        # Smart plug / consumer IoT: usually limited, often MQTT or HTTP.
        smart_plug = AssetProfile(
            name="Akilli Priz",
            expected_services={
                80: ["http"],
                443: ["https"],
                1883: ["mqtt"],
                8883: ["mqtts", "mqtt"],
            },
        )

        # Generic IoT baseline: small surface, web/mqtt optional.
        iot = AssetProfile(
            name="Genel IoT",
            expected_services={
                80: ["http"],
                443: ["https"],
                1883: ["mqtt"],
            },
        )

        return {
            "ip_camera": ip_camera,
            "camera": ip_camera,
            "plc": plc,
            "industrial": plc,
            "smart_plug": smart_plug,
            "plug": smart_plug,
            "iot": iot,
            "home": iot,
        }

    # -------------------------
    # Scoring components
    # -------------------------
    @staticmethod
    def _extract_observed_services(open_ports: List[Dict[str, Any]]) -> Dict[int, str]:
        observed: Dict[int, str] = {}
        for port_info in open_ports:
            try:
                port = int(port_info.get("port"))
            except (TypeError, ValueError):
                continue
            service = str(port_info.get("service") or "").strip().lower()
            if not service:
                service = "unknown"
            observed[port] = service
        return observed

    @staticmethod
    def _profile_anomaly_score(profile: AssetProfile, observed: Dict[int, str]) -> float:
        """0-100: unexpected exposure and missing expected services."""
        expected = profile.expected_services
        if not expected and not observed:
            return 0.0

        unexpected_ports = [p for p in observed.keys() if p not in expected]
        missing_ports = [p for p in expected.keys() if p not in observed]

        mismatch_services = 0
        for port, observed_service in observed.items():
            allowed = [s.lower() for s in expected.get(port, [])]
            if allowed and observed_service not in allowed and observed_service != "unknown":
                mismatch_services += 1

        # Heuristic: unexpected exposure is strongest signal.
        score = 0.0
        score += min(60.0, len(unexpected_ports) * 12.0)
        score += min(25.0, len(missing_ports) * 6.0)
        score += min(15.0, mismatch_services * 7.5)
        return float(max(0.0, min(100.0, score)))

    def _vulnerability_score(self, open_ports: List[Dict[str, Any]]) -> Tuple[float, int]:
        """0-100: based on CVE count and CVSS-like scores when available."""
        total_cves = 0
        cvss_scores: List[float] = []

        for port_info in open_ports or []:
            cves = port_info.get("cves") or []
            for entry in cves:
                total_cves += 1
                cvss_scores.append(self._extract_cvss(entry))

        if total_cves == 0:
            # Still account for visible exposure surface lightly.
            exposure_ports = len(open_ports or [])
            return float(min(20.0, exposure_ports * 4.0)), 0

        # Use both max severity and volume.
        max_cvss = max(cvss_scores) if cvss_scores else self.DEFAULT_CVSS_FALLBACK
        mean_cvss = sum(cvss_scores) / max(1, len(cvss_scores))

        severity = (0.65 * max_cvss + 0.35 * mean_cvss) / 10.0  # 0..1
        volume = min(1.0, total_cves / 12.0)  # saturate after ~12 CVEs

        score = 100.0 * (0.75 * severity + 0.25 * volume)
        return float(max(0.0, min(100.0, score))), int(total_cves)

    def _extract_cvss(self, cve_entry: Any) -> float:
        """Extract CVSS-like score (0..10) from dict entries, else fallback."""
        if isinstance(cve_entry, dict):
            for key in ("cvss", "cvss_score", "cvss_base", "score"):
                if key in cve_entry and cve_entry[key] not in (None, ""):
                    value = self._coerce_float(cve_entry[key])
                    if value is not None:
                        return float(max(0.0, min(10.0, value)))
        return float(self.DEFAULT_CVSS_FALLBACK)

    @staticmethod
    def _coerce_float(value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _runtime_anomaly_score_last_hour(self, asset_id: str) -> float:
        """0-100 from anomaly logs in the last hour (max score wins)."""
        since = utc_now() - timedelta(hours=1)
        session = SessionLocal()
        try:
            logs = (
                session.query(AnomalyLog)
                .filter(AnomalyLog.device_ip == asset_id)
                .filter(AnomalyLog.timestamp >= since)
                .order_by(AnomalyLog.timestamp.desc())
                .all()
            )
            if not logs:
                return 0.0
            # Scores are stored as float (0..1 in current monitor pipeline).
            max_score = 0.0
            for log in logs:
                try:
                    max_score = max(max_score, float(log.score or 0.0))
                except (TypeError, ValueError):
                    continue
            max_score = max(0.0, min(1.0, max_score))
            return float(round(max_score * 100.0, 3))
        finally:
            session.close()

    # -------------------------
    # Trend / spike
    # -------------------------
    def _risk_trend(self, asset_id: str) -> str:
        """Compute risk trend from last points (stable/increasing/decreasing)."""
        points = self._get_recent_risk_points(asset_id, limit=6)
        if len(points) < 3:
            return "stable"
        first = points[0]
        last = points[-1]
        delta = last - first
        if delta >= 7.5:
            return "increasing"
        if delta <= -7.5:
            return "decreasing"
        return "stable"

    def _spike_multiplier(self, asset_id: str, trend: str) -> float:
        """Boost sudden increases with a multiplier."""
        points = self._get_recent_risk_points(asset_id, limit=4)
        if len(points) < 2:
            return 1.0
        last = points[-1]
        prev = points[-2]
        jump = last - prev
        if jump >= 15.0:
            return 1.18 if trend == "increasing" else 1.12
        if jump >= 8.0:
            return 1.08
        return 1.0

    def _get_recent_risk_points(self, asset_id: str, limit: int) -> List[float]:
        session = SessionLocal()
        try:
            rows = (
                session.query(RiskHistory)
                .filter(RiskHistory.device_ip == asset_id)
                .order_by(RiskHistory.timestamp.asc())
                .all()
            )
            scores = [float(row.risk_score or 0.0) for row in rows][-limit:]
            return scores
        finally:
            session.close()

    # -------------------------
    # Weights / status
    # -------------------------
    @staticmethod
    def _weights_for_asset_type(asset_type: str) -> Dict[str, float]:
        asset_type = (asset_type or "iot").lower()

        # Default: vulnerability-led with some runtime anomaly.
        weights = {"profile": 0.25, "vulnerability": 0.45, "anomaly": 0.30}

        # Industrial: anomaly evidence is more critical, profile drift matters.
        if asset_type in {"plc", "industrial"}:
            return {"profile": 0.30, "vulnerability": 0.25, "anomaly": 0.45}

        # Cameras: exposed services/CVEs are usually the main risk vector.
        if asset_type in {"ip_camera", "camera"}:
            return {"profile": 0.25, "vulnerability": 0.55, "anomaly": 0.20}

        # Smart plugs: keep balanced.
        if asset_type in {"smart_plug", "plug", "home"}:
            return {"profile": 0.30, "vulnerability": 0.40, "anomaly": 0.30}

        return weights

    @staticmethod
    def _status_label(score_0_100: float) -> str:
        if score_0_100 > 75:
            return "Critical Risk"
        if score_0_100 > 50:
            return "High Risk"
        if score_0_100 > 25:
            return "Medium Risk"
        return "Safe"

    # -------------------------
    # Persistence access
    # -------------------------
    @staticmethod
    def _get_device(asset_id: str) -> Optional[Device]:
        session = SessionLocal()
        try:
            return session.query(Device).filter(Device.ip == asset_id).first()
        finally:
            session.close()

