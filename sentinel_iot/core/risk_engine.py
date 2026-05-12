from sentinel_iot.database.db import get_setting

class RiskEngine:
    """Calculate device risk from vulnerability exposure and anomaly evidence.

    Public scoring contract:
    - cvss_score is normalized CVSS-like input in the 0.0-10.0 range.
    - anomaly_score is ML anomaly confidence in the 0.0-1.0 range.
    - final score is capped to 100 and classified into Safe/Medium/High/Critical.
    """

    def __init__(self):
        self.weights = {
            "vulnerability": 0.6,
            "anomaly": 0.4,
        }
        self._default_port_modifiers = {
            "21": 1.5, "22": 1.6, "23": 1.7, "445": 1.7, "3389": 1.6, "1883": 1.2, "502": 1.4
        }
        self._default_asset_multipliers = {
            "medical": 1.6, "industrial": 1.4, "iot": 1.1, "home": 1.0, "guest": 0.8
        }

    def get_port_modifiers(self):
        raw = get_setting("port_modifiers", self._default_port_modifiers)
        return {int(k): float(v) for k, v in raw.items()}

    def get_asset_multipliers(self):
        raw = get_setting("asset_multipliers", self._default_asset_multipliers)
        return {str(k): float(v) for k, v in raw.items()}

    def calculate_confidence_score(self, cvss_base, active_verified, passive_traffic, threat_intel):
        """Apply contextual confidence factors to a CVSS-like score."""
        cvss_base = self._validate_range("cvss_base", cvss_base, 0.0, 10.0)
        w_active = 1.5 if active_verified else 0.5
        w_passive = 1.3 if passive_traffic else 0.7
        w_threat = 1.8 if threat_intel else 1.0

        contextual_risk = cvss_base * w_active * w_passive * w_threat
        return min(contextual_risk, 10.0)

    def calculate_device_risk(self, cvss_score, anomaly_score, asset_type="iot", anomaly_confidence=1.0):
        """Combine vulnerability and anomaly components into a final risk score.

        Formula:
        min(100, ((cvss_score * 10) * 0.6 + (anomaly_score * 100 * anomaly_confidence) * 0.4) * asset_multiplier)
        """
        cvss_score = self._validate_range("cvss_score", cvss_score, 0.0, 10.0)
        anomaly_score = self._validate_range("anomaly_score", anomaly_score, 0.0, 1.0)
        anomaly_confidence = self._validate_range("anomaly_confidence", anomaly_confidence, 0.0, 1.0)

        vuln_base = cvss_score * 10
        anomaly_base = anomaly_score * 100 * anomaly_confidence
        asset_mult = self.get_asset_multipliers().get(str(asset_type).lower(), 1.0)

        base_risk = (
            vuln_base * self.weights["vulnerability"]
            + anomaly_base * self.weights["anomaly"]
        )
        final_score = min(100.0, base_risk * asset_mult)

        if final_score > 75:
            status = "Critical Risk"
        elif final_score > 50:
            status = "High Risk"
        elif final_score > 25:
            status = "Medium Risk"
        else:
            status = "Safe"

        return {
            "risk_score": round(float(final_score), 2),
            "status": status,
            "vuln_component": round(float(vuln_base), 2),
            "anomaly_component": round(float(anomaly_base), 2),
            "asset_multiplier": asset_mult,
        }

    def evaluate_device(self, open_ports, anomalies, asset_type="iot"):
        """Evaluate a scanned device using service exposure, CVEs, and anomalies."""
        open_ports = open_ports or []
        anomalies = anomalies or []

        base_ports_score = 0.0
        total_cves = 0
        max_contextual_cve_risk = 0.0
        has_anomalies = bool(anomalies)

        if open_ports:
            is_dict_format = isinstance(open_ports[0], dict)
            base_ports_score = min(len(open_ports) * 5, 20)
            current_port_modifiers = self.get_port_modifiers()

            for p_info in open_ports:
                port_num = self._extract_port_number(p_info, is_dict_format)
                port_mult = current_port_modifiers.get(port_num, 1.0)

                if port_mult > 1.0:
                    base_ports_score += 10 * port_mult

                cve_items = p_info.get("cves", []) if is_dict_format else []
                for cve_item in cve_items:
                    total_cves += 1
                    cvss_base = self._extract_cvss(cve_item)
                    adjusted_cvss = min(10.0, cvss_base * port_mult)
                    confidence_score = self.calculate_confidence_score(
                        cvss_base=adjusted_cvss,
                        active_verified=False,
                        passive_traffic=has_anomalies,
                        threat_intel=False,
                    )
                    max_contextual_cve_risk = max(max_contextual_cve_risk, confidence_score)

        cvss_input = max_contextual_cve_risk if total_cves > 0 else min(base_ports_score, 100) / 10.0

        anomaly_input = 0.0
        max_confidence = 1.0
        if anomalies:
            anomaly_input = max(self._validate_range("anomaly.score", item.get("score", 0.0), 0.0, 1.0) for item in anomalies)
            max_confidence = max(self._validate_range("anomaly.confidence", item.get("confidence", 0.8), 0.0, 1.0) for item in anomalies)

        risk_result = self.calculate_device_risk(
            cvss_input,
            anomaly_input,
            asset_type=asset_type,
            anomaly_confidence=max_confidence,
        )

        return {
            "risk_score": risk_result["risk_score"],
            "status": risk_result["status"],
            "vuln_component": risk_result["vuln_component"],
            "anomaly_component": risk_result["anomaly_component"],
            "total_cves": total_cves,
            "max_contextual_score": round(float(max_contextual_cve_risk), 2),
            "raw_anomaly_score": round(float(anomaly_input), 4),
            "context_factors": {
                "asset_type": asset_type,
                "asset_multiplier": risk_result["asset_multiplier"],
                "anomaly_confidence": max_confidence,
                "total_cves": total_cves,
                "max_contextual_score": round(float(max_contextual_cve_risk), 2),
            },
        }

    def _extract_port_number(self, port_info, is_dict_format):
        value = port_info.get("port") if is_dict_format else port_info[0]
        try:
            return int(value)
        except (TypeError, ValueError):
            return -1

    def _extract_cvss(self, cve_item):
        if isinstance(cve_item, dict):
            for key in ("cvss", "cvss_score", "cvss_base", "score"):
                if key in cve_item and cve_item[key] not in (None, ""):
                    return self._validate_range("cve.cvss", cve_item[key], 0.0, 10.0)
        return 7.0

    def _validate_range(self, name, value, minimum, maximum):
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} gecersiz: sayisal deger olmali.") from exc

        if number < minimum or number > maximum:
            raise ValueError(f"{name} gecersiz: {minimum} ile {maximum} arasinda olmali.")
        return number
