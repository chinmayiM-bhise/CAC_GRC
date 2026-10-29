from sqlalchemy import Column, String, Integer, DateTime, JSON
from app.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now

class AssessmentRun(Base, TimestampMixin):
    """
    Historical log of compliance assessment runs.
    Records duration, scope, pass/fail totals, and runner errors.
    """
    __tablename__ = "assessment_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    run_type = Column(String(50), default="MANUAL_ADHOC", nullable=False) # SCHEDULED, MANUAL_ADHOC, EXPERIMENTAL
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, default=0, nullable=False)
    
    total_tests = Column(Integer, default=0, nullable=False)
    passed_count = Column(Integer, default=0, nullable=False)
    failed_count = Column(Integer, default=0, nullable=False)
    error_count = Column(Integer, default=0, nullable=False)
    
    execution_summary = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<AssessmentRun(id='{self.id}', type='{self.run_type}', passed={self.passed_count}, failed={self.failed_count})>"
