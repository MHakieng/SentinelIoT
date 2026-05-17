from fastapi import APIRouter, Depends, BackgroundTasks
from typing import List
import uuid
from sentinel_iot.services.monitor_service import MonitorService
from sentinel_iot.services.job_manager import JobManager
from sentinel_iot.api.dependencies import get_monitor_service, get_job_manager, get_devices_db
from sentinel_iot.schemas.flow_schema import (
    FlowMetrics,
    PacketInfo,
    TrafficHistoryPoint,
    TopologyNode,
    TopologyLink,
    TopologyResponse,
)
from sentinel_iot.schemas.job_schema import JobCreateResponse, JobControlResponse, MonitorRuntimeStatus
from sentinel_iot.database.db import get_all_devices

router = APIRouter(prefix="/monitor", tags=["Monitoring"])

@router.get("/packets", response_model=List[PacketInfo])
def get_live_packets(service: MonitorService = Depends(get_monitor_service)):
    """Return the most recently captured raw packets for the dashboard."""
    return service.get_live_packets_snapshot()

@router.get("/flows", response_model=List[FlowMetrics])
def get_live_flows(service: MonitorService = Depends(get_monitor_service)):
    """Return the aggregated flow summary with anomaly labels."""
    return service.get_live_flows_snapshot()

@router.get("/history", response_model=List[TrafficHistoryPoint])
def get_traffic_history(service: MonitorService = Depends(get_monitor_service)):
    """Return recent historical traffic metrics."""
    return service.get_traffic_history_snapshot()

@router.get("/topology", response_model=TopologyResponse)
def get_topology(service: MonitorService = Depends(get_monitor_service)):
    """Return nodes and edges for network topology visualization."""
    devices = get_all_devices()
    device_map = {device["ip"]: device for device in devices}
    flows = service.get_live_flows_snapshot()

    nodes = [
        TopologyNode(
            id="sentinel-gw",
            label="Ağ Geçidi",
            type="gateway",
            ip="192.168.1.1",
            risk_score=0.0,
            status="Safe",
        )
    ]
    links = []

    for ip, device in device_map.items():
        nodes.append(
            TopologyNode(
                id=ip,
                label=f"{device.get('vendor', 'Unknown')} ({ip})",
                type="device",
                ip=ip,
                risk_score=device.get("risk_score", 0.0),
                status=device.get("status", "Safe"),
            )
        )
        links.append(
            TopologyLink(
                source="sentinel-gw",
                target=ip,
                anomaly=False,
                protocol="ARP/Discovery",
                score=0.0,
            )
        )

    for flow in flows:
        src, dst = flow["src_ip"], flow["dst_ip"]
        if src in device_map or dst in device_map:
            links.append(
                TopologyLink(
                    source=src if src in device_map else "sentinel-gw",
                    target=dst if dst in device_map else "sentinel-gw",
                    anomaly=flow.get("label") == 1,
                    protocol=flow.get("protocol_name", str(flow.get("protocol", "Unknown"))),
                    score=flow.get("anomaly_score", 0.0),
                    src_port=flow.get("src_port"),
                    dst_port=flow.get("dst_port"),
                    packet_count=flow.get("packet_count", 0),
                    byte_count=flow.get("byte_count", 0),
                )
            )

    return TopologyResponse(nodes=nodes, links=links)

@router.post("/live/start", response_model=JobCreateResponse)
def start_live_test(
    background_tasks: BackgroundTasks, 
    duration: int = 5,
    service: MonitorService = Depends(get_monitor_service),
    job_manager: JobManager = Depends(get_job_manager),
    devices_db = Depends(get_devices_db)
):
    """Start continuous live traffic capture and anomaly detection."""
    if service.get_runtime_status().get("is_running"):
        active_job = job_manager.get_active_job("sniffing")
        active_job_id = active_job["id"] if active_job else "active"
        return {"message": "Live test already running", "job_id": active_job_id, "status": "running"}
        
    job_id = str(uuid.uuid4())
    job_manager.create_job(job_id, "sniffing")
    service.mark_monitor_pending(job_id, duration)
    
    background_tasks.add_task(service.start_live_monitor, job_id, devices_db, duration)
    return {"message": "Continuous live test started", "job_id": job_id, "status": "pending"}


@router.get("/live/status", response_model=MonitorRuntimeStatus)
def get_live_test_status(service: MonitorService = Depends(get_monitor_service)):
    """Return a stable runtime snapshot for live monitoring state."""
    return service.get_runtime_status()

@router.post("/live/stop", response_model=JobControlResponse)
def stop_live_test(
    service: MonitorService = Depends(get_monitor_service),
    job_manager: JobManager = Depends(get_job_manager)
):
    """Stop the continuous live traffic capture."""
    active_job_id = service.stop_live_monitor()
    if active_job_id:
        job_manager.update_job(active_job_id, message="Stop requested. Waiting for current capture window to finish.")
        return {"message": "Stopping live test", "job_id": active_job_id, "status": "stopping"}
    return {"message": "No active live test", "job_id": None, "status": "idle"}
