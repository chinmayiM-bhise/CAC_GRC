from sqlalchemy import Column, String, Text, Float, Boolean, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid

class PolicyMapping(Base, TimestampMixin):
    """
    Mapping linking an internal Corporate Policy to an authoritative Framework Control.
    Evaluated in Dimension 1 (Mapping Accuracy / Quality).
    Supports reviewer audit history, rationale, and duplicate mapping prevention.
    """
    __tablename__ = "policy_mappings"
    __table_args__ = (
        UniqueConstraint("policy_id", "control_id", name="uq_policy_control_mapping"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    policy_id = Column(String(36), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(50), ForeignKey("framework_controls.control_id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Ground truth & validation status: PROPOSED/SUGGESTED/DRAFT, REVIEWED, APPROVED/HUMAN_APPROVED, REJECTED
    mapping_status = Column(String(30), default="PROPOSED", nullable=False)
    is_ground_truth = Column(Boolean, default=False, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False) # 1.0 for ground truth; algorithmic confidence for candidates
    rationale = Column(Text, nullable=True) # Justification for mapping validity

    # Review workflow & audit
    reviewer = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)

    # Relationships
    policy = relationship("Policy", back_populates="mappings")
    framework_control = relationship("FrameworkControl", back_populates="mappings")
    test_definitions = relationship("TestDefinition", back_populates="mapping", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<PolicyMapping(policy_id='{self.policy_id}', control_id='{self.control_id}', status='{self.mapping_status}')>"
