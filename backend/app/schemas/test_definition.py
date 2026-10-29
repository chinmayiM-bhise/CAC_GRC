from pydantic import BaseModel, ConfigDict
from typing import Optional, Any, Dict
from datetime import datetime

class TestDefinitionBase(BaseModel):
    __test__ = False
    test_id: str
    mapping_id: str
    tier: int
    target_type: str
    name: str
    description: Optional[str] = None
    is_required: bool = True
    is_behavioral: bool = False
    max_ttl_hours: int = 24
    test_spec: Dict[str, Any]

class TestDefinitionCreate(TestDefinitionBase):
    pass

class TestDefinitionResponse(TestDefinitionBase):
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
