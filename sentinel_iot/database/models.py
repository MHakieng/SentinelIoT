from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True)
    mac = Column(String)
    vendor = Column(String, default="Unknown")
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String, default="Safe")
    risk_score = Column(Float, default=0.0)
    open_ports = Column(JSON, default=[])
    total_cves = Column(Integer, default=0)
    asset_type = Column(String, default="iot") # medical, industrial, iot, home
    priority = Column(Integer, default=1) # 1: Low, 2: Medium, 3: High
    risk_breakdown = Column(JSON, default={"vuln": 0, "anomaly": 0})

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    devices_found = Column(Integer, default=0)
    scan_type = Column(String, default="full")

class AnomalyLog(Base):
    __tablename__ = "anomaly_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    device_ip = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    type = Column(String) # e.g., "dos", "scan", "mitm"
    score = Column(Float)
    details = Column(JSON)

class RiskHistory(Base):
    __tablename__ = "risk_history"
    
    id = Column(Integer, primary_key=True, index=True)
    device_ip = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Float)
    vuln_component = Column(Float)
    anomaly_component = Column(Float)

