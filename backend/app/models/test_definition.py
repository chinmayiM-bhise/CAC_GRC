from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin

class TestDefinition(Base, TimestampMixin):
    """
    Compliance-as-Code (CaC) executable test specification.
    Defines either Tier 1 (Passive Config) or Tier 2 (Active Behavioral) checks.
    """
    __tablename__ = "test_definitions"
    __test__ = False # Prevent pytest from collecting ORM class as test suite

    test_id = Column(String(100), primary_key=True, index=True) # e.g. "TEST-VM-SSH-LOCKOUT-T2"
    mapping_id = Column(String(36), ForeignKey("policy_mappings.id", ondelete="CASCADE"), nullable=False, index=True)
    
    tier = Column(Integer, nullable=False) # 1 = Static Config Check, 2 = Active Behavioral Probe
    target_type = Column(String(50), nullable=False) # "LINUX_VM", "POSTGRES_DB", "GITEA_VCS"
    name = Column(String(255), nullable=False)
    description = Column(String(500), nullable=True)
    
    is_required = Column(Boolean, default=True, nullable=False) # Distinguishes mandatory checks from optional supporting checks
    is_behavioral = Column(Boolean, default=False, nullable=False) # True if active behavioral probe
    max_ttl_hours = Column(Integer, default=24, nullable=False) # Evidence expires after this window
    
    # Executable JSON test specification (commands, expected patterns, timeouts, etc.)
    test_spec = Column(JSON, nullable=False)

    # Relationships
    mapping = relationship("PolicyMapping", back_populates="test_definitions")
    evidence_records = relationship("EvidenceRecord", back_populates="test_definition", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<TestDefinition(id='{self.test_id}', tier={self.tier}, target='{self.target_type}')>"
