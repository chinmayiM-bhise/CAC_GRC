from sqlalchemy import Column, String, DateTime, Text, JSON
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now

class AuditLog(Base, TimestampMixin):
    """
    Append-only administrative audit log recording privileged user and system actions.
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    actor = Column(String(100), default="SYSTEM", nullable=False)
    action = Column(String(100), nullable=False, index=True) # e.g. "INJECT_CHAOS_DRIFT", "RESTORE_BASELINE"
    target = Column(String(100), nullable=True)
    outcome = Column(String(30), default="SUCCESS", nullable=False) # SUCCESS, FAILURE, ERROR
    details = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<AuditLog(actor='{self.actor}', action='{self.action}', outcome='{self.outcome}')>"
