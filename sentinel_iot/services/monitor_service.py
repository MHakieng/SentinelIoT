import time
import threading
import ipaddress
import logging
import math
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional
from sentinel_iot.monitor.packet_capture import start_capture
from sentinel_iot.monitor.feature_extractor import extract_features
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.ml.device_classifier import classify_device
from sentinel_iot.ml.device_class_scoring import score_flow_with_device_context
from sentinel_iot.database.db import get_all_devices, upsert_device, save_anomaly_log, save_risk_history
from sentinel_iot.services.context_risk_engine import ContextualRiskEngine
from sentinel_iot.services.job_manager import JobManager

logger = logging.getLogger(__name__)

class MonitorService:
    """Service for managing network monitoring, packet capture, and live anomaly detection."""
    
    def __init__(self, risk_engine: ContextualRiskEngine, anomaly_model: AnomalyModel, job_manager: JobManager):
        self.risk_engine = risk_engine
        self.anomaly_model = anomaly_model
        self.job_manager = job_manager
        self.live_testing_active = False
        self.live_packets = []
        self.live_flows = {}
        self.total_flows_seen = 0
        self.flow_buffer_limit = 500
        self.traffic_history = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self.active_job_id: Optional[str] = None
        self._db_executor = ThreadPoolExecutor(max_workers=1)
        self.monitor_status = {
            "status": "idle",
            "active_job_id": None,
            "started_at": None,
            "updated_at": None,
            "message": "CanlÄ± izleme Ã§alÄ±ÅŸmÄ±yor",
            "error": None,
            "is_running": False,
            "last_event_at": None,
            "summary": {
                "packets_captured": 0,
                "flows_tracked": 0,
                "total_flows_seen": 0,
                "flow_buffer_limit": self.flow_buffer_limit,
                "history_points": 0,
                "last_interval_packets": 0,
            },
            "capture_window_seconds": None,
            "last_completed_at": None,
        }

    @staticmethod
    def _timestamp() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _update_monitor_status(self, **kwargs):
        now = self._timestamp()
        if any(key in kwargs for key in ("status", "message", "error", "summary")):
            kwargs.setdefault("last_event_at", now)
        kwargs.setdefault("updated_at", now)
        if "status" in kwargs:
            kwargs.setdefault("is_running", kwargs["status"] in {"pending", "running", "stopping"})
        self.monitor_status.update(kwargs)

    def _build_monitor_summary(self, last_interval_packets: int = 0) -> Dict[str, int]:
        return {
            "packets_captured": len(self.live_packets),
            "flows_tracked": len(self.live_flows),
            "total_flows_seen": self.total_flows_seen,
            "flow_buffer_limit": self.flow_buffer_limit,
            "history_points": len(self.traffic_history),
            "last_interval_packets": last_interval_packets,
        }

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            if value is None or isinstance(value, bool):
                return default
            numeric = float(value)
            return numeric if math.isfinite(numeric) else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _device_class_context(devices_db: Dict[str, Any], ip: Any, prefix: str) -> Dict[str, Any]:
        if not isinstance(devices_db, dict) or not ip:
            return {}
        device = devices_db.get(str(ip))
        if not isinstance(device, dict):
            return {}

        context = {}
        class_value = device.get("device_class")
        confidence_value = device.get("device_class_confidence")
        if class_value:
            context[f"{prefix}_device_class"] = class_value
        if confidence_value is not None:
            context[f"{prefix}_device_class_confidence"] = MonitorService._safe_float(confidence_value)
        return context

    @staticmethod
    def _build_device_context_db(devices_db: Dict[str, Any]) -> Dict[str, Any]:
        merged = {}
        if isinstance(devices_db, dict):
            merged.update({str(ip): device for ip, device in devices_db.items() if isinstance(device, dict)})

        try:
            for device in get_all_devices():
                ip = device.get("ip")
                if not ip:
                    continue
                existing = dict(merged.get(str(ip), {}))
                existing.update(device)
                if not existing.get("device_class"):
                    try:
                        classification = classify_device(existing)
                        existing.update({
                            "device_class": classification.get("device_class", "unknown"),
                            "device_class_confidence": classification.get("confidence", 0.0),
                            "device_class_evidence": classification.get("evidence", []),
                            "device_class_method": classification.get("method", "rule_based"),
                        })
                    except Exception:
                        existing.update({
                            "device_class": "unknown",
                            "device_class_confidence": 0.0,
                            "device_class_evidence": ["Device classification failed during monitor context lookup"],
                            "device_class_method": "rule_based",
                        })
                merged[str(ip)] = existing
        except Exception as exc:
            logger.warning("Could not load persisted devices for monitor context: %s", exc)

        return merged

    def _flow_with_device_context(self, flow: Dict[str, Any], devices_db: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(flow)
        enriched.update(self._device_class_context(devices_db, flow.get("src_ip"), "source"))
        enriched.update(self._device_class_context(devices_db, flow.get("dst_ip"), "destination"))
        return enriched

    def get_runtime_status(self) -> Dict[str, Any]:
        active_job = self.job_manager.get_active_job("sniffing")
        latest_job = self.job_manager.get_latest_job("sniffing")

        if active_job:
            return {
                "status": active_job.get("status", "running"),
                "active_job_id": active_job.get("id"),
                "started_at": active_job.get("started_at"),
                "updated_at": active_job.get("updated_at"),
                "message": active_job.get("message") or self.monitor_status.get("message"),
                "error": active_job.get("error") or self.monitor_status.get("error"),
                "is_running": active_job.get("is_running", True),
                "last_event_at": active_job.get("last_event_at") or self.monitor_status.get("last_event_at"),
                "summary": active_job.get("summary") or self.monitor_status.get("summary", {}),
                "capture_window_seconds": self.monitor_status.get("capture_window_seconds"),
                "last_completed_at": self.monitor_status.get("last_completed_at"),
            }

        if latest_job:
            return {
                "status": latest_job.get("status", self.monitor_status.get("status", "idle")),
                "active_job_id": None,
                "started_at": latest_job.get("started_at"),
                "updated_at": latest_job.get("updated_at"),
                "message": latest_job.get("message") or self.monitor_status.get("message"),
                "error": latest_job.get("error") or self.monitor_status.get("error"),
                "is_running": False,
                "last_event_at": latest_job.get("last_event_at") or self.monitor_status.get("last_event_at"),
                "summary": latest_job.get("summary") or self.monitor_status.get("summary", {}),
                "capture_window_seconds": self.monitor_status.get("capture_window_seconds"),
                "last_completed_at": self.monitor_status.get("last_completed_at"),
            }

        return dict(self.monitor_status)

    def mark_monitor_pending(self, job_id: str, duration: int):
        with self._lock:
            self.active_job_id = job_id
            self._update_monitor_status(
                status="pending",
                active_job_id=job_id,
                started_at=self._timestamp(),
                message="CanlÄ± izleme kuyruÄŸa alÄ±ndÄ±",
                error=None,
                is_running=True,
                capture_window_seconds=duration,
                summary=self._build_monitor_summary(),
            )

    @staticmethod
    def _protocol_name(protocol: Any) -> str:
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        if isinstance(protocol, str):
            return protocol
        return protocol_map.get(protocol, f"IP/{protocol}")

    def get_live_packets_snapshot(self):
        """Return a stable snapshot of the live packet buffer."""
        with self._lock:
            return list(self.live_packets)

    def get_live_flows_snapshot(self):
        """Return a stable snapshot of the live flow map."""
        with self._lock:
            flows = []
            for flow in self.live_flows.values():
                snapshot = dict(flow)
                snapshot["protocol_name"] = self._protocol_name(snapshot.get("protocol"))
                flows.append(snapshot)

            return sorted(
                flows,
                key=lambda flow: (
                    -int(flow.get("label", 0)),
                    -float(flow.get("anomaly_score", 0.0)),
                    -int(flow.get("packet_count", 0)),
                    flow.get("flow_id", ""),
                ),
            )

    def get_live_flow_scores_snapshot(self):
        """Return the current explainable flow scoring snapshot."""
        with self._lock:
            scored = []
            for flow in self.live_flows.values():
                snapshot = dict(flow.get("scoring_breakdown") or {})
                if not snapshot:
                    snapshot = score_flow_with_device_context(
                        flow,
                        ml_raw_score=self._safe_float(flow.get("ml_raw_score", flow.get("anomaly_score"))),
                        ml_anomaly_score=self._safe_float(flow.get("ml_anomaly_score", flow.get("anomaly_score"))),
                    )
                scored.append(snapshot)

            return sorted(
                scored,
                key=lambda flow: (
                    -float(flow.get("final_flow_risk", 0.0)),
                    flow.get("flow_id", ""),
                ),
            )

    def get_traffic_history_snapshot(self):
        """Return a stable snapshot of traffic history."""
        with self._lock:
            return list(self.traffic_history)

    def start_live_monitor(self, job_id: str, devices_db: Dict[str, Any], duration: int = 5):
        """Main background task for continuous sniffing and detection."""
        with self._lock:
            self.live_testing_active = True
            self.active_job_id = job_id
            self._stop_event.clear()
            started_at = self._timestamp()
            self._update_monitor_status(
                status="running",
                active_job_id=job_id,
                started_at=started_at,
                message="CanlÄ± izleme etkin",
                error=None,
                is_running=True,
                capture_window_seconds=duration,
                summary=self._build_monitor_summary(),
            )

        self.job_manager.update_job(
            job_id,
            status="running",
            message="CanlÄ± izleme etkin",
            summary=self.monitor_status["summary"],
        )

        try:
            while not self._stop_event.is_set():
                with self._lock:
                    if not self.live_testing_active:
                        break

                packets = start_capture(duration=duration, output_file=None, verbose=False)
                if self._stop_event.is_set():
                    break

                if packets is None:
                    raise RuntimeError("Packet capture failed or returned no result")

                if not packets:
                    logger.info("Live monitor captured no packets during the last window.")
                    summary = self._build_monitor_summary()
                    self._update_monitor_status(message="Son aralÄ±kta paket yakalanmadÄ±", summary=summary)
                    self.job_manager.update_job(job_id, message="Son aralÄ±kta paket yakalanmadÄ±", summary=summary)
                    continue

                try:
                    new_pkts = self._parse_packets_for_ui(packets)
                    with self._lock:
                        self.live_packets.extend(new_pkts)
                        if len(self.live_packets) > 100:
                            del self.live_packets[:-100]

                    features = extract_features(packets=packets)
                    current_time = time.time()
                    with self._lock:
                        for f in features:
                            fid = f['flow_id']
                            if fid not in self.live_flows:
                                self.total_flows_seen += 1
                                self.live_flows[fid] = f
                                self.live_flows[fid].update({
                                    "anomaly_score": 0.0, 
                                    "label": 0,
                                    "last_seen": current_time
                                })
                            else:
                                self.live_flows[fid]['packet_count'] += f['packet_count']
                                self.live_flows[fid]['byte_count'] += f['byte_count']
                                self.live_flows[fid]['duration'] = max(self.live_flows[fid]['duration'], f['duration'])
                                self.live_flows[fid]['last_seen'] = current_time
                                
                        # Prune old flows to prevent memory leaks
                        if len(self.live_flows) > self.flow_buffer_limit:
                            sorted_flows = sorted(
                                self.live_flows.items(),
                                key=lambda item: item[1].get('last_seen', 0),
                                reverse=True
                            )
                            self.live_flows = dict(sorted_flows[:self.flow_buffer_limit])

                    if features:
                        anomalies = self._score_features_and_collect_anomalies(features, devices_db)
                        self._process_anomalies(anomalies, devices_db)
                        
                        # CanlÄ± akÄ±ÅŸ ile sÃ¼rekli Ã¶ÄŸrenmeyi (sÃ¼rekli eÄŸitim) asenkron olarak tetikle

                    total_packets = sum(f.get('packet_count', 0) for f in features) if features else 0
                    with self._lock:
                        self.traffic_history.append({"time": time.strftime("%H:%M:%S"), "packets": total_packets})
                        if len(self.traffic_history) > 15:
                            self.traffic_history.pop(0)

                    summary = self._build_monitor_summary(last_interval_packets=total_packets)
                    self._update_monitor_status(message=f"CanlÄ± izleme etkin. Son aralÄ±ktaki paket sayÄ±sÄ±: {total_packets}", summary=summary)
                    self.job_manager.update_job(job_id, message=f"CanlÄ± izleme etkin. Son aralÄ±ktaki paket sayÄ±sÄ±: {total_packets}", summary=summary)

                except Exception as inner_e:
                    logger.warning("Error processing packet window, dropping corrupted flows. Reason: %s", inner_e, exc_info=True)
                    continue

        except Exception as e:
            logger.error("Monitor Service Error: %s", e, exc_info=True)
            failure_summary = self._build_monitor_summary()
            self.job_manager.finish_job(
                job_id,
                status="failed",
                result={"last_known_packets": len(self.live_packets), "last_known_flows": len(self.live_flows)},
                message="CanlÄ± izleme baÅŸarÄ±sÄ±z oldu",
                error=str(e),
                summary=failure_summary,
            )
            self._update_monitor_status(
                status="failed",
                active_job_id=None,
                is_running=False,
                message="CanlÄ± izleme baÅŸarÄ±sÄ±z oldu",
                error=str(e),
                summary=failure_summary,
                last_completed_at=self._timestamp(),
            )
        else:
            completed_summary = self._build_monitor_summary()
            self.job_manager.finish_job(
                job_id,
                result={"last_known_packets": len(self.live_packets), "last_known_flows": len(self.live_flows)},
                message="CanlÄ± izleme durduruldu",
                summary=completed_summary,
            )
            self._update_monitor_status(
                status="completed",
                active_job_id=None,
                is_running=False,
                message="CanlÄ± izleme durduruldu",
                error=None,
                summary=completed_summary,
                last_completed_at=self._timestamp(),
            )
        finally:
            try:
                with self._lock:
                    self.live_testing_active = False
                    self.active_job_id = None
                    self._stop_event.clear()
            except Exception:
                logger.exception("Failed to finalize monitor state cleanly")

    def stop_live_monitor(self):
        """Signal the live monitor loop to stop after the current capture window."""
        with self._lock:
            if not self.live_testing_active:
                return None
            self.live_testing_active = False
            self._stop_event.set()
            self._update_monitor_status(
                status="stopping",
                active_job_id=self.active_job_id,
                is_running=True,
                message="Durdurma istendi. Mevcut yakalama penceresinin bitmesi bekleniyor.",
                error=None,
            )
            return self.active_job_id

    def _parse_packets_for_ui(self, packets):
        new_pkts = []
        for pkt in packets:
            try:
                if pkt.haslayer(scapy.IP):
                    src_port = pkt[scapy.TCP].sport if pkt.haslayer(scapy.TCP) else (pkt[scapy.UDP].sport if pkt.haslayer(scapy.UDP) else 0)
                    dst_port = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else (pkt[scapy.UDP].dport if pkt.haslayer(scapy.UDP) else 0)
                    proto_name = "TCP" if pkt.haslayer(scapy.TCP) else ("UDP" if pkt.haslayer(scapy.UDP) else "ICMP")
                    
                    info = ""
                    if pkt.haslayer(scapy.Raw):
                        try:
                            info = pkt[scapy.Raw].load.decode('ascii', errors='ignore')[:50]
                        except:
                            info = "Ä°kili Veri"
                    
                    flow_id = f"{pkt[scapy.IP].src}:{src_port}->{pkt[scapy.IP].dst}:{dst_port} [{pkt[scapy.IP].proto}]"
                    new_pkts.append({
                        "timestamp": time.strftime("%H:%M:%S", time.localtime(float(pkt.time))),
                        "source_ip": pkt[scapy.IP].src,
                        "destination_ip": pkt[scapy.IP].dst,
                        "source_port": src_port,
                        "destination_port": dst_port,
                        "protocol": proto_name,
                        "packet_length": len(pkt),
                        "info": info.strip() or f"Len: {len(pkt)}",
                        "flow_id": flow_id
                    })
            except Exception as e:
                logger.warning("Error parsing packet for UI: %s", e)
                continue
        return new_pkts

    def _score_features_and_collect_anomalies(self, features, devices_db=None):
        anomalies = []
        devices_db = self._build_device_context_db(devices_db or {})
        for flow in features:
            analysis = self.anomaly_model.detect_anomaly(flow)
            ml_score = self._safe_float(analysis.get("score"))
            ml_raw_score = self._safe_float(analysis.get("raw_score"), default=ml_score)
            contextual_flow = self._flow_with_device_context(flow, devices_db)
            scored = score_flow_with_device_context(contextual_flow, ml_raw_score=ml_raw_score, ml_anomaly_score=ml_score)
            fid = flow.get("flow_id")

            with self._lock:
                if fid and fid in self.live_flows:
                    for field in (
                        "source_device_class",
                        "source_device_class_confidence",
                        "destination_device_class",
                        "destination_device_class_confidence",
                    ):
                        if field in contextual_flow:
                            self.live_flows[fid][field] = contextual_flow[field]
                    self.live_flows[fid]["ml_raw_score"] = ml_raw_score
                    self.live_flows[fid]["ml_anomaly_score"] = ml_score
                    self.live_flows[fid]["anomaly_score"] = ml_score
                    self.live_flows[fid]["confidence"] = self._safe_float(analysis.get("confidence"), default=ml_score)
                    calibrated_anomaly = scored.get("decision") == "anomaly"
                    self.live_flows[fid]["label"] = 1 if calibrated_anomaly else 0
                    self.live_flows[fid]["reward_points"] = scored["reward_points"]
                    self.live_flows[fid]["penalty_points"] = scored["penalty_points"]
                    self.live_flows[fid]["final_flow_risk"] = scored["final_flow_risk"]
                    self.live_flows[fid]["severity"] = scored["severity"]
                    self.live_flows[fid]["class_aware_adjustment"] = scored["class_aware_adjustment"]
                    self.live_flows[fid]["class_aware_reasons"] = scored["class_aware_reasons"]
                    self.live_flows[fid]["decision"] = scored["decision"]
                    self.live_flows[fid]["decision_source"] = scored["decision_source"]
                    self.live_flows[fid]["reasons"] = scored["reasons"]
                    self.live_flows[fid]["features"] = scored["features"]
                    self.live_flows[fid]["scoring_breakdown"] = scored
                    if analysis.get("model"):
                        self.live_flows[fid]["model"] = analysis.get("model")

            if scored.get("decision") == "anomaly":
                anomalies.append({
                    "flow_id": fid,
                    "target": flow.get("dst_ip", "unknown"),
                    "type": "statistical_anomaly",
                    "score": ml_score,
                    "confidence": self._safe_float(analysis.get("confidence"), default=ml_score),
                    "model": analysis.get("model"),
                    "reasons": scored["reasons"] or [
                        f"Statistical anomaly (Score: {ml_score}, Conf: {analysis.get('confidence', ml_score)})"
                    ],
                    "metrics": self.anomaly_model.metrics,
                    "flow_scoring": scored,
                })

        return anomalies

    def _process_anomalies(self, anomalies, devices_db):
        for a in anomalies:
            with self._lock:
                # Update flow visualization
                fid = a.get('flow_id')
                if fid and fid in self.live_flows:
                    self.live_flows[fid]['anomaly_score'] = a['score']
                    self.live_flows[fid]['confidence'] = a.get('confidence', 1.0)
                    self.live_flows[fid]['label'] = 1
                    if a.get('model'):
                        self.live_flows[fid]['model'] = a.get('model')
                
            # Offload synchronous database writes to a background thread
            self._db_executor.submit(self._persist_anomaly_task, a, devices_db)

    def _persist_anomaly_task(self, a, devices_db):
        # Update device risk
        ip = a['target']
        try: 
            if not ipaddress.ip_address(ip).is_private: return
        except: return
        
        if ip not in devices_db:
            devices_db[ip] = self._create_default_device(ip)
        
        # Re-calculate Risk
        # Persist the anomaly evidence first, then compute contextual risk from DB state.
        upsert_device(devices_db[ip])
        save_anomaly_log(ip, a.get('type', 'Unknown'), a['score'], a)

        risk = self.risk_engine.calculate_risk(ip)
        devices_db[ip]['risk_score'] = risk.get('risk_score', devices_db[ip].get('risk_score', 0.0))
        devices_db[ip]['status'] = risk.get('status', devices_db[ip].get('status', 'Safe'))
        devices_db[ip]['risk_breakdown']['vuln'] = risk.get('vuln_component', devices_db[ip]['risk_breakdown'].get('vuln', 0.0))
        devices_db[ip]['risk_breakdown']['anomaly'] = risk.get('anomaly_component', devices_db[ip]['risk_breakdown'].get('anomaly', 0.0))
        
        # Persistence
        upsert_ok = upsert_device(devices_db[ip])
        risk_history_ok = save_risk_history(
            ip,
            float(risk.get('risk_score', 0.0)),
            float(risk.get('vuln_component', 0.0)),
            float(risk.get('anomaly_component', 0.0)),
        )
        if not (upsert_ok and risk_history_ok):
            logger.warning("Monitor persistence was partially unsuccessful for device %s", ip)

    def _create_default_device(self, ip):
        return {
            "ip": ip, "mac": "Unknown", "vendor": "Unknown", "risk_score": 0,
            "status": "Safe", "open_ports": [], "total_cves": 0,
            "asset_type": "iot", "priority": 1, "risk_breakdown": {"vuln": 0, "anomaly": 0}
        }
