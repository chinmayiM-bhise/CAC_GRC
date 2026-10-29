from sqlalchemy import Column, String, Text, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now

class Policy(Base, TimestampMixin):
    """
    Internal corporate security policy statement and lifecycle record.
    Supports complete governance workflow: drafting, review, approval, revision, and deprecation.
    """
    __tablename__ = "policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    policy_code = Column(String(50), unique=True, index=True, nullable=False) # e.g. "POL-IAM-001"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), nullable=False) # e.g. "Identity & Access Management", "Audit & Accountability"
    version = Column(String(20), default="1.0", nullable=False)
    owner = Column(String(100), default="CISO Office")

    # Governance & Lifecycle metadata
    purpose = Column(Text, nullable=True)
    statement = Column(Text, nullable=True)
    scope = Column(String(255), default="Enterprise Infrastructure & Systems", nullable=True)
    lifecycle_status = Column(String(30), default="DRAFT", nullable=False) # DRAFT, UNDER_REVIEW, APPROVED, REJECTED, DEPRECATED
    approver = Column(String(100), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    effective_date = Column(DateTime, nullable=True)
    review_date = Column(DateTime, nullable=True)
    is_sample = Column(Boolean, default=False, nullable=False) # Clearly flags sample policies as examples
    required_evidence_desc = Column(Text, nullable=True)

    # Relationships
    mappings = relationship("PolicyMapping", back_populates="policy", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Policy(code='{self.policy_code}', title='{self.title}', status='{self.lifecycle_status}')>"
