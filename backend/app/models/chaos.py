from sqlalchemy import Column, String, DateTime, Text, JSON
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now

class ChaosDriftRecord(Base, TimestampMixin):
    """
    Persistent audit record of an active or restored security drift scenario.
    Differentiates between simulated experiment flags and live target mutations.
    Maintains the formal 8-phase verifiable drift lifecycle:
    PRECHECK -> BASELINE_CAPTURED -> MUTATION_APPLIED -> MUTATION_VERIFIED ->
    ASSESSMENT_EXECUTED -> DETECTION_VERIFIED -> RESTORATION_EXECUTED -> RECOVERY_VERIFIED.
    """
    __tablename__ = "chaos_drifts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    drift_id = Column(String(100), nullable=False, index=True)
    drift_type = Column(String(30), default="SIMULATED", nullable=False) # SIMULATED or LIVE_LAB_MUTATION
    target_type = Column(String(50), nullable=False) # LINUX_VM, POSTGRES_DB
    status = Column(String(30), default="ACTIVE", nullable=False, index=True) # ACTIVE, RESTORED, FAILED
    
    # 8-Phase Lifecycle
    lifecycle_phase = Column(String(50), default="MUTATION_APPLIED", nullable=False)
    lifecycle_history = Column(JSON, default=list, nullable=False) # List of phase transition events with timestamps and logs
    detection_result = Column(JSON, nullable=True) # Results of detection assessment sweep
    recovery_result = Column(JSON, nullable=True) # Results of post-restoration verification assessment
    
    injected_at = Column(DateTime, default=utc_now, nullable=False)
    restored_at = Column(DateTime, nullable=True)
    
    precondition_state = Column(JSON, nullable=True)
    postcondition_verification = Column(JSON, nullable=True)
    actor = Column(String(100), default="CLI_USER", nullable=False)
    audit_notes = Column(Text, nullable=True)

    def __repr__(self):
        return f"<ChaosDriftRecord(drift_id='{self.drift_id}', type='{self.drift_type}', phase='{self.lifecycle_phase}', status='{self.status}')>"
