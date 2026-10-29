from sqlalchemy import Column, String, DateTime, Text, Integer, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now

class Finding(Base, TimestampMixin):
    """
    Compliance and security findings generated from assessment failures.
    Tracks remediation lifecycle: OPEN -> IN_PROGRESS -> READY_FOR_RETEST -> VERIFIED_RESOLVED.
    Supports deduplication, formal risk-waivers, and retest-gated resolution.
    """
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    control_id = Column(String(50), ForeignKey("framework_controls.control_id", ondelete="CASCADE"), nullable=False, index=True)
    test_id = Column(String(100), nullable=False)
    target_type = Column(String(50), default="LINUX_VM", nullable=True)
    target_host = Column(String(100), nullable=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="MEDIUM", nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(30), default="OPEN", nullable=False, index=True) # OPEN, IN_PROGRESS, READY_FOR_RETEST, VERIFIED_RESOLVED, RISK_ACCEPTED
    
    assigned_owner = Column(String(100), default="Unassigned")
    due_date = Column(DateTime, nullable=True)
    remediation_notes = Column(Text, nullable=True)
    
    # Recurrence & Tracking
    occurrence_count = Column(Integer, default=1, nullable=False)
    first_detected_at = Column(DateTime, default=utc_now, nullable=False)
    last_detected_at = Column(DateTime, default=utc_now, nullable=False)
    
    # Verified Resolution
    resolved_at = Column(DateTime, nullable=True)
    verified_resolved_at = Column(DateTime, nullable=True)
    resolution_run_id = Column(String(100), nullable=True)
    
    # Risk Acceptance / Waiver Workflow
    risk_waiver_justification = Column(Text, nullable=True)
    risk_waiver_approved_by = Column(String(100), nullable=True)
    risk_waiver_expires_at = Column(DateTime, nullable=True)

    # Relationships
    framework_control = relationship("FrameworkControl")

    def __repr__(self):
        return f"<Finding(id='{self.id}', control='{self.control_id}', severity='{self.severity}', status='{self.status}')>"
