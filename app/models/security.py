from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Enum as SQLEnum
from app.core.database import Base
from app.security.base import ScanStatus


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    client_ip = Column(String, index=True)
    user_id = Column(Integer, nullable=True)
    endpoint = Column(String)

    status = Column(SQLEnum(ScanStatus))
    scanner_name = Column(String)
    risk_score = Column(Float, default=0.0)

    request_text = Column(String)
    sanitized_text = Column(String)
    metadata_log = Column(JSON)