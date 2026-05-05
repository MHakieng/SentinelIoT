import time
import threading
import ipaddress
import logging
import scapy.all as scapy
from typing import Dict, Any, Optional
from sentinel_iot.monitor.packet_capture import start_capture
from sentinel_iot.monitor.feature_extractor import extract_features
from sentinel_iot.core.risk_engine import RiskEngine
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.database.db import upsert_device, save_anomaly_log, save_risk_history
from sentinel_iot.services.job_manager import JobManager

logger = logging.getLogger(__name__)

class MonitorService:
    """Service for managing network monitoring, packet capture, and live anomaly detection."""
    
    def __init__(self, risk_engine: RiskEngine, anomaly_model: AnomalyModel, job_manager: JobManager):
        self.risk_engine = risk_engine
        self.anomaly_model = anomaly_model
        self.job_manager = job_manager
        self.live_testing_active = False
        self.live_packets = []
        self.live_flows = {}
        self.traffic_history = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self.active_job_id: Optional[str] = None
        self.monitor_status = {
            "status": "idle",
            "active_job_id": None,
            "started_at": None,
            "updated_at": None,
            "message": "Canlı izleme çalışmıyor",
            "error": None,
            "is_running": False,
            "last_event_at": None,
            "summary": {
                "packets_captured": 0,
                "flows_tracked": 0,
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
                message="Canlı izleme kuyruğa alındı",
                error=None,
                is_running=True,
                capture_window_seconds=duration,
                summary={
                    "packets_captured": len(self.live_packets),
                    "flows_tracked": len(self.live_flows),
                    "history_points": len(self.traffic_history),
                    "last_interval_packets": 0,
                },
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
                message="Canlı izleme etkin",
                error=None,
                is_running=True,
                capture_window_seconds=duration,
                summary={
                    "packets_captured": 0,
                    "flows_tracked": len(self.live_flows),
                    "history_points": len(self.traffic_history),
                    "last_interval_packets": 0,
                },
            )

        self.job_manager.update_job(
            job_id,
            status="running",
            message="Canlı izleme etkin",
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
                    summary = {
                        "packets_captured": len(self.live_packets),
                        "flows_tracked": len(self.live_flows),
                        "history_points": len(self.traffic_history),
                        "last_interval_packets": 0,
                    }
                    self._update_monitor_status(message="Son aralıkta paket yakalanmadı", summary=summary)
                    self.job_manager.update_job(job_id, message="Son aralıkta paket yakalanmadı", summary=summary)
                    continue

                new_pkts = self._parse_packets_for_ui(packets)
                with self._lock:
                    self.live_packets.extend(new_pkts)
                    if len(self.live_packets) > 100:
                        del self.live_packets[:-100]

                features = extract_features(packets=packets)
                with self._lock:
                    for f in features:
                        fid = f['flow_id']
                        if fid not in self.live_flows:
                            self.live_flows[fid] = f
                            self.live_flows[fid].update({"anomaly_score": 0.0, "label": 0})
                        else:
                            self.live_flows[fid]['packet_count'] += f['packet_count']
                            self.live_flows[fid]['byte_count'] += f['byte_count']
                            self.live_flows[fid]['duration'] = max(self.live_flows[fid]['duration'], f['duration'])

                if features:
                    anomalies = self.anomaly_model.detect(features)
                    self._process_anomalies(anomalies, devices_db)

                total_packets = sum(f.get('packet_count', 0) for f in features) if features else 0
                with self._lock:
                    self.traffic_history.append({"time": time.strftime("%H:%M:%S"), "packets": total_packets})
                    if len(self.traffic_history) > 15:
                        self.traffic_history.pop(0)

                summary = {
                    "packets_captured": len(self.live_packets),
                    "flows_tracked": len(self.live_flows),
                    "history_points": len(self.traffic_history),
                    "last_interval_packets": total_packets,
                }
                self._update_monitor_status(message=f"Canlı izleme etkin. Son aralıktaki paket sayısı: {total_packets}", summary=summary)
                self.job_manager.update_job(job_id, message=f"Canlı izleme etkin. Son aralıktaki paket sayısı: {total_packets}", summary=summary)

        except Exception as e:
            logger.error("Monitor Service Error: %s", e, exc_info=True)
            failure_summary = {
                "packets_captured": len(self.live_packets),
                "flows_tracked": len(self.live_flows),
                "history_points": len(self.traffic_history),
                "last_interval_packets": 0,
            }
            self.job_manager.finish_job(
                job_id,
                status="failed",
                result={"last_known_packets": len(self.live_packets), "last_known_flows": len(self.live_flows)},
                message="Canlı izleme başarısız oldu",
                error=str(e),
                summary=failure_summary,
            )
            self._update_monitor_status(
                status="failed",
                active_job_id=None,
                is_running=False,
                message="Canlı izleme başarısız oldu",
                error=str(e),
                summary=failure_summary,
                last_completed_at=self._timestamp(),
            )
        else:
            completed_summary = {
                "packets_captured": len(self.live_packets),
                "flows_tracked": len(self.live_flows),
                "history_points": len(self.traffic_history),
                "last_interval_packets": 0,
            }
            self.job_manager.finish_job(
                job_id,
                result={"last_known_packets": len(self.live_packets), "last_known_flows": len(self.live_flows)},
                message="Canlı izleme durduruldu",
                summary=completed_summary,
            )
            self._update_monitor_status(
                status="completed",
                active_job_id=None,
                is_running=False,
                message="Canlı izleme durduruldu",
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
            if pkt.haslayer(scapy.IP):
                src_port = pkt[scapy.TCP].sport if pkt.haslayer(scapy.TCP) else (pkt[scapy.UDP].sport if pkt.haslayer(scapy.UDP) else 0)
                dst_port = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else (pkt[scapy.UDP].dport if pkt.haslayer(scapy.UDP) else 0)
                proto_name = "TCP" if pkt.haslayer(scapy.TCP) else ("UDP" if pkt.haslayer(scapy.UDP) else "ICMP")
                
                info = ""
                if pkt.haslayer(scapy.Raw):
                    try:
                        info = pkt[scapy.Raw].load.decode('ascii', errors='ignore')[:50]
                    except:
                        info = "İkili Veri"
                
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
        return new_pkts

    def _process_anomalies(self, anomalies, devices_db):
        with self._lock:
            for a in anomalies:
                # Update flow visualization
                fid = a.get('flow_id')
                if fid and fid in self.live_flows:
                    self.live_flows[fid]['anomaly_score'] = a['score']
                    self.live_flows[fid]['confidence'] = a.get('confidence', 1.0)
                    self.live_flows[fid]['label'] = 1
                
                # Update device risk
                ip = a['target']
                try: 
                    if not ipaddress.ip_address(ip).is_private: continue
                except: continue
                
                if ip not in devices_db:
                    devices_db[ip] = self._create_default_device(ip)
                
                # Re-calculate Risk
                risk = self.risk_engine.evaluate_device(
                    devices_db[ip].get('open_ports', []), 
                    [a], 
                    asset_type=devices_db[ip].get('asset_type', 'iot')
                )
                devices_db[ip]['risk_score'] = risk['risk_score']
                devices_db[ip]['status'] = risk['status']
                devices_db[ip]['risk_breakdown']['anomaly'] = risk['anomaly_component']
                
                # Persistence
                upsert_ok = upsert_device(devices_db[ip])
                anomaly_log_ok = save_anomaly_log(ip, a.get('type', 'Unknown'), a['score'], a)
                risk_history_ok = save_risk_history(ip, risk['risk_score'], risk['vuln_component'], risk['anomaly_component'])
                if not (upsert_ok and anomaly_log_ok and risk_history_ok):
                    logger.warning("Monitor persistence was partially unsuccessful for device %s", ip)

    def _create_default_device(self, ip):
        return {
            "ip": ip, "mac": "Unknown", "vendor": "Unknown", "risk_score": 0,
            "status": "Safe", "open_ports": [], "total_cves": 0,
            "asset_type": "iot", "priority": 1, "risk_breakdown": {"vuln": 0, "anomaly": 0}
        }
