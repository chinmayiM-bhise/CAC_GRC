from sqlalchemy import Column, String, Text, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin

class FrameworkControl(Base, TimestampMixin):
    """
    Authoritative compliance framework control (ISO/IEC 27001:2022 or NIST SP 800-53 Rev 5).
    Differentiates between technically automated controls (assessed via SSH/DB)
    and organizational/procedural controls requiring manual/documentary evidence.
    Supports parent-control and control-enhancement relationships and lifecycle status.
    """
    __tablename__ = "framework_controls"

    control_id = Column(String(50), primary_key=True, index=True) # e.g. "NIST-AC-7", "ISO-A.8.5", "NIST-AC-2(1)"
    framework_name = Column(String(50), index=True, nullable=False) # e.g. "NIST_SP_800_53_R5", "ISO_27001_2022"
    framework_version = Column(String(50), default="2022", nullable=True) # e.g. "2022", "Rev 5.2.0"
    control_code = Column(String(50), nullable=False) # e.g. "AC-7", "A.8.5", "AC-2(1)"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    domain_family = Column(String(100), nullable=False) # e.g. "Access Control", "Technological Controls"
    
    # Method: TECHNICAL_AUTOMATED, ORGANIZATIONAL_MANUAL, HYBRID
    assessment_method = Column(String(50), default="TECHNICAL_AUTOMATED", nullable=False)
    official_requirement = Column(Text, nullable=True)
    guidance = Column(Text, nullable=True)

    # Enhancements and catalog status
    is_enhancement = Column(Boolean, default=False, nullable=False)
    parent_control_id = Column(String(50), nullable=True, index=True) # e.g. "NIST-AC-2"
    status = Column(String(30), default="ACTIVE", nullable=False) # ACTIVE, WITHDRAWN
    provenance = Column(String(255), nullable=True)

    # Relationships
    mappings = relationship("PolicyMapping", back_populates="framework_control")
    scores = relationship("EWCESScore", back_populates="framework_control")

    def __repr__(self):
        return f"<FrameworkControl(id='{self.control_id}', framework='{self.framework_name}', status='{self.status}')>"
