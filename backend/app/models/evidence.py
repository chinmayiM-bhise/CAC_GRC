from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now

class EvidenceRecord(Base, TimestampMixin):
    """
    Immutable Evidence Vault Record.
    Contains raw telemetry, timestamps, execution metadata, and cryptographic hashes.
    """
    __tablename__ = "evidence_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    test_id = Column(String(100), ForeignKey("test_definitions.test_id", ondelete="CASCADE"), nullable=False, index=True)
    
    collected_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    
    # 1 = Explicitly Passed, -1 = Explicitly Failed, 0 = Inconclusive / Runner Error
    result_code = Column(Integer, nullable=False)
    
    # Provenance: LIVE_TARGET, SIMULATED_LAB, CACHED
    evidence_provenance = Column(String(50), default="LIVE_TARGET", nullable=False)
    
    # Execution Status: SUCCESS, FAILURE, CONNECTION_ERROR, TIMEOUT, SIMULATED
    execution_status = Column(String(50), default="SUCCESS", nullable=False)
    
    # Raw execution telemetry (command stdout, stderr, exit code, duration_ms)
    raw_telemetry = Column(JSON, nullable=False)
    
    # Cryptographic integrity fields
    payload_sha256 = Column(String(64), nullable=False, index=True) # SHA-256 of canonical payload
    previous_record_hash = Column(String(64), nullable=True) # Sequential previous-hash linkage
    signature_valid = Column(Boolean, default=True, nullable=False) # Checksum integrity verified

    # Relationships
    test_definition = relationship("TestDefinition", back_populates="evidence_records")

    def __repr__(self):
        return f"<EvidenceRecord(id='{self.id}', test='{self.test_id}', result={self.result_code})>"
