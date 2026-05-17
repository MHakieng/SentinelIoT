from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class FlowBase(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

class FlowMetrics(FlowBase):
    packet_count: int
    byte_count: int
    duration: float
    avg_packet_size: float
    mean_iat: float
    var_iat: float
    packet_rate: float = 0.0
    # ── Genişletilmiş öznitelikler ──
    tcp_syn_ratio: float = 0.0
    tcp_synack_ratio: float = 0.0
    unique_dst_ip_count: int = 0
    unique_dst_port_count: int = 0
    rst_syn_ratio: float = 0.0
    dns_query_response_ratio: float = 0.0
    unique_domain_count: int = 0
    pkt_size_variance: float = 0.0
    bytes_per_second: float = 0.0
    small_pkt_ratio: float = 0.0
    large_pkt_ratio: float = 0.0
    # ── UI / anomali meta verileri ──
    protocol_name: str = "Unknown"
    anomaly_score: float = 0.0
    ml_raw_score: float = 0.0
    ml_anomaly_score: float = 0.0
    reward_points: int = 0
    penalty_points: int = 0
    final_flow_risk: float = 0.0
    severity: str = "low"
    reasons: List[str] = Field(default_factory=list)
    source_device_class: Optional[str] = None
    source_device_class_confidence: Optional[float] = None
    destination_device_class: Optional[str] = None
    destination_device_class_confidence: Optional[float] = None
    class_aware_adjustment: Optional[float] = None
    class_aware_reasons: List[str] = Field(default_factory=list)
    decision: Optional[str] = None
    decision_source: Optional[str] = None
    features: Dict[str, Any] = Field(default_factory=dict)
    scoring_breakdown: Optional[Dict[str, Any]] = None
    label: int = 0
    confidence: float = 1.0
    model: Optional[Dict[str, Any]] = None

class PacketInfo(BaseModel):
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_length: int
    info: str
    flow_id: str


class TrafficHistoryPoint(BaseModel):
    time: str
    packets: int


class TopologyNode(BaseModel):
    id: str
    label: str
    type: str
    ip: str
    risk_score: float = 0.0
    status: str = "Safe"


class TopologyLink(BaseModel):
    source: str
    target: str
    anomaly: bool = False
    protocol: str = "Unknown"
    score: float = 0.0
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packet_count: int = 0
    byte_count: int = 0


class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    links: List[TopologyLink]
