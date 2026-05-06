"""Database engine, session management, and CRUD operations for SentinelIoT."""

import os
import time
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sentinel_iot.database.models import Base, Device, ScanHistory, AnomalyLog, RiskHistory, utc_now

logger = logging.getLogger(__name__)

# SQLite file in the project root (relative to sentinel_iot)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel_iot.db")
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


def _commit_with_retry(session, operation_name: str, retries: int = 3, delay_s: float = 0.15):
    """Commit writes with short retry/backoff for transient SQLite lock errors."""
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            last_error = exc
            is_locked_error = "locked" in str(exc).lower()
            logger.warning(
                "DB %s attempt %s/%s failed: %s",
                operation_name,
                attempt,
                retries,
                exc,
            )
            if not is_locked_error or attempt == retries:
                break
            time.sleep(delay_s * attempt)

    logger.error("DB %s failed after retries: %s", operation_name, last_error, exc_info=True)
    return False


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def upsert_device(device_data: dict):
    """Insert or update a device record."""
    session = SessionLocal()
    try:
        existing = session.query(Device).filter(Device.ip == device_data["ip"]).first()
        if existing:
            existing.mac = device_data.get("mac", existing.mac)
            existing.vendor = device_data.get("vendor", existing.vendor)
            existing.risk_score = device_data.get("risk_score", existing.risk_score)
            existing.status = device_data.get("status", existing.status)
            existing.open_ports = device_data.get("open_ports", existing.open_ports)
            existing.total_cves = device_data.get("total_cves", existing.total_cves)
            existing.asset_type = device_data.get("asset_type", existing.asset_type)
            existing.priority = device_data.get("priority", existing.priority)
            existing.risk_breakdown = device_data.get("risk_breakdown", existing.risk_breakdown)
            existing.last_seen = utc_now()
        else:
            device = Device(
                ip=device_data["ip"],
                mac=device_data.get("mac", "Unknown"),
                vendor=device_data.get("vendor", "Unknown"),
                risk_score=device_data.get("risk_score", 0.0),
                status=device_data.get("status", "Safe"),
                open_ports=device_data.get("open_ports", []),
                total_cves=device_data.get("total_cves", 0),
                asset_type=device_data.get("asset_type", "iot"),
                priority=device_data.get("priority", 1),
                risk_breakdown=device_data.get("risk_breakdown", {"vuln": 0, "anomaly": 0})
            )
            session.add(device)
        return _commit_with_retry(session, "upsert_device")
    except Exception as e:
        session.rollback()
        logger.error("DB upsert error for %s: %s", device_data.get("ip"), e, exc_info=True)
        return False
    finally:
        session.close()


def get_all_devices() -> list:
    """Return all devices as a list of dicts (API-compatible format)."""
    session = SessionLocal()
    try:
        devices = session.query(Device).all()
        return [
            {
                "ip": d.ip,
                "mac": d.mac,
                "vendor": d.vendor,
                "risk_score": d.risk_score,
                "status": d.status,
                "open_ports": d.open_ports or [],
                "total_cves": d.total_cves,
                "asset_type": d.asset_type or "iot",
                "priority": d.priority or 1,
                "risk_breakdown": d.risk_breakdown or {"vuln": 0, "anomaly": 0}
            }
            for d in devices
        ]
    finally:
        session.close()


def get_device_by_ip(device_ip: str) -> dict | None:
    """Return a single device by IP in API-compatible format."""
    session = SessionLocal()
    try:
        device = session.query(Device).filter(Device.ip == device_ip).first()
        if not device:
            return None

        return {
            "ip": device.ip,
            "mac": device.mac,
            "vendor": device.vendor,
            "risk_score": device.risk_score,
            "status": device.status,
            "open_ports": device.open_ports or [],
            "total_cves": device.total_cves,
            "asset_type": device.asset_type or "iot",
            "priority": device.priority or 1,
            "risk_breakdown": device.risk_breakdown or {"vuln": 0, "anomaly": 0},
        }
    finally:
        session.close()


def save_scan_history(devices_found: int, scan_type: str = "full"):
    """Record a scan event."""
    session = SessionLocal()
    try:
        record = ScanHistory(devices_found=devices_found, scan_type=scan_type)
        session.add(record)
        return _commit_with_retry(session, "save_scan_history")
    except Exception as e:
        session.rollback()
        logger.error("DB scan history error: %s", e, exc_info=True)
        return False
    finally:
        session.close()

def save_anomaly_log(device_ip: str, anomaly_type: str, score: float, details: dict):
    """Record an anomaly event."""
    session = SessionLocal()
    try:
        log = AnomalyLog(device_ip=device_ip, type=anomaly_type, score=score, details=details)
        session.add(log)
        return _commit_with_retry(session, "save_anomaly_log")
    except Exception as e:
        session.rollback()
        logger.error("DB anomaly log error for %s: %s", device_ip, e, exc_info=True)
        return False
    finally:
        session.close()

def save_risk_history(device_ip: str, risk_score: float, vuln: float, anomaly: float):
    """Record a risk score snapshot."""
    session = SessionLocal()
    try:
        history = RiskHistory(
            device_ip=device_ip, 
            risk_score=risk_score,
            vuln_component=vuln,
            anomaly_component=anomaly
        )
        session.add(history)
        return _commit_with_retry(session, "save_risk_history")
    except Exception as e:
        session.rollback()
        logger.error("DB risk history error for %s: %s", device_ip, e, exc_info=True)
        return False
    finally:
        session.close()


def get_device_risk_history(device_ip: str) -> list:
    """Return risk history for a specific device."""
    session = SessionLocal()
    try:
        history = session.query(RiskHistory).filter(RiskHistory.device_ip == device_ip).order_by(RiskHistory.timestamp.asc()).all()
        return [
            {
                "timestamp": h.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "risk_score": h.risk_score,
                "vuln": h.vuln_component,
                "anomaly": h.anomaly_component
            }
            for h in history
        ]
    finally:
        session.close()


def get_device_anomaly_logs(device_ip: str) -> list:
    """Return anomaly logs for a specific device."""
    session = SessionLocal()
    try:
        logs = session.query(AnomalyLog).filter(AnomalyLog.device_ip == device_ip).order_by(AnomalyLog.timestamp.desc()).all()
        return [
            {
                "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "type": l.type,
                "score": l.score,
                "details": l.details
            }
            for l in logs
        ]
    finally:
        session.close()
