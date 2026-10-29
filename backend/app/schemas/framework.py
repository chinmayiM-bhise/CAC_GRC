from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class FrameworkControlBase(BaseModel):
    control_id: str
    framework_name: str
    framework_version: Optional[str] = "2022"
    control_code: str
    title: str
    description: str
    domain_family: str
    assessment_method: str = "TECHNICAL_AUTOMATED"
    official_requirement: Optional[str] = None
    guidance: Optional[str] = None
    is_enhancement: bool = False
    parent_control_id: Optional[str] = None
    status: str = "ACTIVE"
    provenance: Optional[str] = None

class FrameworkControlCreate(FrameworkControlBase):
    pass

class FrameworkControlResponse(FrameworkControlBase):
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
