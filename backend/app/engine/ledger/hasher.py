import hashlib
import json
from typing import Any, Dict

def canonical_json_dump(data: Any) -> str:
    """Serializes data to canonical JSON format (sorted keys, no whitespace) for stable hashing."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)

def compute_evidence_hash(test_id: str, collected_at_iso: str, result_code: int, raw_telemetry: Dict[str, Any]) -> str:
    """
    Computes a canonical SHA-256 digest over the evidence payload.
    Ensures non-repudiation: if any telemetry field or timestamp changes, the hash changes.
    """
    canonical_payload = canonical_json_dump({
        "test_id": test_id,
        "collected_at": collected_at_iso,
        "result_code": result_code,
        "telemetry": raw_telemetry
    })
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
