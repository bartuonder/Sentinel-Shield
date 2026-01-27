from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.security.base import ScanStatus
from datetime import datetime

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    client_ip = Column(String, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    user = relationship("User", back_populates="logs")

    endpoint = Column(String)
    status = Column(SQLEnum(ScanStatus))
    scanner_name = Column(String)
    risk_score = Column(Float, default=0.0)

    request_text = Column(String)
    sanitized_text = Column(String)
    metadata_log = Column(JSON)


class BlacklistedIP(Base):
    __tablename__ = "blacklisted_ips"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    ip_address = Column(String, index=True,
                        nullable=False)
    reason = Column(String)
    banned_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    user = relationship("User")