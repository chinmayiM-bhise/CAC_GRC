from pydantic import BaseModel, ConfigDict
from typing import Optional, Any, Dict
from datetime import datetime

class EWCESScoreBase(BaseModel):
    control_id: str
    state: str
    freshness_score: float
    has_tier2_evidence: bool = False
    hash_integrity_verified: bool = True
    diagnostic_summary: str
    evaluation_metadata: Optional[Dict[str, Any]] = None

class EWCESScoreCreate(EWCESScoreBase):
    pass

class EWCESScoreResponse(EWCESScoreBase):
    id: str
    evaluated_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
