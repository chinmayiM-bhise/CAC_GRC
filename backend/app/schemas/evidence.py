from pydantic import BaseModel, ConfigDict
from typing import Optional, Any, Dict
from datetime import datetime

class EvidenceRecordBase(BaseModel):
    test_id: str
    result_code: int
    execution_status: str = "SUCCESS"
    evidence_provenance: str = "LIVE_TARGET"
    raw_telemetry: Dict[str, Any]
    payload_sha256: str
    previous_record_hash: Optional[str] = None
    signature_valid: bool = True

class EvidenceRecordCreate(EvidenceRecordBase):
    pass

class EvidenceRecordResponse(EvidenceRecordBase):
    id: str
    collected_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CheckpointPayloadSchema(BaseModel):
    checkpoint_timestamp: str
    format_version: str
    last_record_hash: str
    last_record_id: Optional[str] = None
    last_record_sequence: int
    ledger_id: str


class CheckpointArtifactSchema(BaseModel):
    format_version: str
    checkpoint_payload: CheckpointPayloadSchema
    checkpoint_sha256: str
    signature: str
    signature_algorithm: str
    public_key_pem: str


class CheckpointVerificationResponse(BaseModel):
    is_valid: bool
    signature_valid: bool
    ledger_matched: bool
    status: str
    violations: list[str]
    checkpoint_summary: Dict[str, Any]
