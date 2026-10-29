from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class FindingBase(BaseModel):
    control_id: str
    test_id: str
    title: str
    description: str
    severity: str = "MEDIUM" # CRITICAL, HIGH, MEDIUM, LOW
    status: str = "OPEN" # OPEN, IN_PROGRESS, READY_FOR_RETEST, VERIFIED_RESOLVED, RISK_ACCEPTED
    assigned_owner: str = "Unassigned"
    due_date: Optional[datetime] = None
    remediation_notes: Optional[str] = None
    target_type: Optional[str] = "LINUX_VM"
    target_host: Optional[str] = None
    occurrence_count: int = 1
    first_detected_at: Optional[datetime] = None
    last_detected_at: Optional[datetime] = None
    verified_resolved_at: Optional[datetime] = None
    resolution_run_id: Optional[str] = None
    risk_waiver_justification: Optional[str] = None
    risk_waiver_approved_by: Optional[str] = None
    risk_waiver_expires_at: Optional[datetime] = None

class FindingCreate(FindingBase):
    pass

class FindingUpdate(BaseModel):
    status: Optional[str] = None # OPEN, IN_PROGRESS, READY_FOR_RETEST
    severity: Optional[str] = None
    assigned_owner: Optional[str] = None
    remediation_notes: Optional[str] = None
    due_date: Optional[datetime] = None

class FindingRiskWaiverRequest(BaseModel):
    justification: str
    approved_by: str
    expires_at: datetime
    notes: Optional[str] = None

class FindingResponse(FindingBase):
    id: str
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
