from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class PolicyBase(BaseModel):
    policy_code: str
    title: str
    description: str
    category: str
    version: str = "1.0"
    owner: str = "CISO Office"
    purpose: Optional[str] = None
    statement: Optional[str] = None
    scope: Optional[str] = "Enterprise Infrastructure & Systems"
    lifecycle_status: str = "DRAFT"
    approver: Optional[str] = None
    rejection_reason: Optional[str] = None
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    is_sample: bool = False
    required_evidence_desc: Optional[str] = None

class PolicyCreate(BaseModel):
    policy_code: str
    title: str
    description: str
    category: str
    version: str = "1.0"
    owner: Optional[str] = "CISO Office"
    purpose: Optional[str] = None
    statement: Optional[str] = None
    scope: Optional[str] = "Enterprise Infrastructure & Systems"
    required_evidence_desc: Optional[str] = None

class PolicyUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    version: Optional[str] = None
    owner: Optional[str] = None
    purpose: Optional[str] = None
    statement: Optional[str] = None
    scope: Optional[str] = None
    required_evidence_desc: Optional[str] = None
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    approver: Optional[str] = None

class PolicyReviewRequest(BaseModel):
    action: str # "APPROVE" or "REJECT"
    approver: str
    rejection_reason: Optional[str] = None
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None

class PolicyResponse(PolicyBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
