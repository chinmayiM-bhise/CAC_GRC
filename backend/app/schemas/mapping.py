from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.schemas.policy import PolicyResponse
from app.schemas.framework import FrameworkControlResponse

class PolicyMappingBase(BaseModel):
    policy_id: str
    control_id: str
    mapping_status: str = "PROPOSED" # PROPOSED, REVIEWED, APPROVED, REJECTED (also accepts HUMAN_APPROVED, DRAFT, SUGGESTED)
    is_ground_truth: bool = False
    confidence_score: float = 1.0
    rationale: Optional[str] = None
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None

class PolicyMappingCreate(BaseModel):
    policy_id: str
    control_id: str
    mapping_status: Optional[str] = "PROPOSED"
    confidence_score: float = 1.0
    rationale: Optional[str] = None

class PolicyMappingResponse(PolicyMappingBase):
    id: str
    created_at: datetime
    updated_at: datetime
    policy: Optional[PolicyResponse] = None
    framework_control: Optional[FrameworkControlResponse] = None

    model_config = ConfigDict(from_attributes=True)

class MappingSuggestionResponse(BaseModel):
    mapping_id: Optional[str] = None
    current_review_status: Optional[str] = None
    policy_id: str
    policy_code: str
    policy_title: str
    control_id: str
    control_title: str
    framework_name: str
    confidence_score: float
    mapping_status: str = "SUGGESTED"
    is_ground_truth: bool = False
    requires_human_review: bool = True
    matched_concepts: List[str] = []
    rationale: str

class MappingReviewRequest(BaseModel):
    status: str # "APPROVED" / "HUMAN_APPROVED", "REJECTED", "REVIEWED"
    rationale: Optional[str] = None
    review_notes: Optional[str] = None
    reviewer: Optional[str] = None

class MappingAuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    actor: str
    action: str
    target: Optional[str] = None
    outcome: str
    details: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)

class FrameworkCoverageMetrics(BaseModel):
    total_catalog_controls: int
    base_controls_count: int
    enhancements_count: int
    withdrawn_controls_count: int
    mapped_controls_count: int
    unmapped_controls_count: int
    approved_mapped_controls_count: int
    unreviewed_mapped_controls_count: int
    technically_assessed_controls_count: int
    mapping_coverage_pct: float
    approved_coverage_pct: float
    technical_assessment_pct: float

class MappingCoverageReport(BaseModel):
    iso_27001: FrameworkCoverageMetrics
    nist_800_53: FrameworkCoverageMetrics
    combined: FrameworkCoverageMetrics
    mappings_by_status: Dict[str, int]
    unmapped_control_ids: List[str]
    unreviewed_control_ids: List[str]
    policies_without_mappings: List[str]
