from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime

class AssessmentRunBase(BaseModel):
    run_type: str = "MANUAL_ADHOC"
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: int = 0
    total_tests: int = 0
    passed_count: int = 0
    failed_count: int = 0
    error_count: int = 0
    execution_summary: Optional[Dict[str, Any]] = None

class AssessmentRunResponse(AssessmentRunBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssessmentTaskAcceptedResponse(BaseModel):
    task_id: str
    status: str = "QUEUED"
    message: str
    created_at: str
    poll_url: str


class AssessmentTaskStatusResponse(BaseModel):
    task_id: str
    status: str  # QUEUED, RUNNING, COMPLETED, FAILED
    run_type: str = "MANUAL_ADHOC"
    allow_simulation: bool = True
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    assessment_id: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

