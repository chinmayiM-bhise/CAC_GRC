from sqlalchemy import Column, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now

class EWCESScore(Base, TimestampMixin):
    """
    Evidence-Weighted Control Effectiveness Score (EW-CES).
    Records the computed 4-State assurance status for an authoritative Framework Control.
    """
    __tablename__ = "ew_ces_scores"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    control_id = Column(String(50), ForeignKey("framework_controls.control_id", ondelete="CASCADE"), nullable=False, index=True)
    
    evaluated_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    
    # 4-State Classification: VERIFIED_EFFECTIVE, CONFIG_COMPLIANT, DEFICIENT, UNKNOWN
    state = Column(String(30), nullable=False, index=True)
    
    # Mathematical factors
    freshness_score = Column(Float, nullable=False) # F(t) from 0.0 (stale) to 1.0 (fresh)
    has_tier2_evidence = Column(Boolean, default=False, nullable=False) # Whether behavioral validation was performed
    hash_integrity_verified = Column(Boolean, default=True, nullable=False) # Whether cryptographic hash chain held
    
    # Explainability & audit defensibility
    diagnostic_summary = Column(Text, nullable=False)
    evaluation_metadata = Column(JSON, nullable=True) # Full breakdown of evaluated sub-tests and weights

    # Relationships
    framework_control = relationship("FrameworkControl", back_populates="scores")

    def __repr__(self):
        return f"<EWCESScore(control='{self.control_id}', state='{self.state}', freshness={self.freshness_score:.2f})>"
