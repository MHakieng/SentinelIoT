from pydantic import BaseModel
from typing import Optional, List

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
    protocol_name: str = "Unknown"
    anomaly_score: float = 0.0
    label: int = 0
    confidence: float = 1.0

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
