"""
CAC-GRC Evidence Ledger & Cryptographic Vault.

Threat Model & Cryptographic Guarantees:
----------------------------------------
1. Guarantees:
   - Tamper Evidence: Detects any unauthorized post-hoc modification of raw telemetry,
     result codes, test identifiers, or collection timestamps via canonical SHA-256 digests.
   - Sequence Integrity: Sequential hash chaining (where record N points to payload SHA-256 of record N-1)
     prevents undetected record deletion, insertion, or reordering. Note: This is an unbroken linear hash chain, not a Merkle tree.
   - Reproducibility: Deterministic key-sorted JSON canonicalization ensures identical
     cryptographic hashes regardless of Python dict insertion order or formatting.

2. Limitations & Honest Scope:
   - Trust Boundary: The evidence ledger operates inside the application database. An attacker
     with arbitrary database write access and execution control could recompute the entire hash chain
     from a tampered record forward unless periodically anchored to an external trusted log or remote sink.
   - Non-Repudiation: SHA-256 digests provide cryptographic tamper-detection, not asymmetric digital
     signatures. True legal non-repudiation requires external PKI / asymmetric HSM signing keys.
   - Clock Dependence: Timestamps rely on host system UTC clock. Mitigated by strict ISO-8601 normalization.
"""

import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Tuple, List, Optional, Dict, Any
from app.models.evidence import EvidenceRecord
from app.models.base import utc_now
from app.engine.runner.base import TestResult
from app.engine.ledger.hasher import compute_evidence_hash
from app.engine.scoring.decay import ensure_utc


def _get_ordered_records(db: Session, desc: bool = False):
    """
    Returns evidence records query strictly ordered by creation timestamp
    and underlying database insertion sequence (rowid on SQLite, id on generic).
    Guarantees deterministic, unambiguous sequential ordering even if multiple
    records share identical timestamps down to the microsecond.
    """
    is_sqlite = False
    try:
        bind = db.get_bind()
        is_sqlite = (bind.dialect.name == "sqlite")
    except Exception:
        pass

    if is_sqlite:
        order_clause = [EvidenceRecord.created_at.desc(), text("rowid DESC")] if desc else [EvidenceRecord.created_at.asc(), text("rowid ASC")]
    else:
        order_clause = [EvidenceRecord.created_at.desc(), EvidenceRecord.id.desc()] if desc else [EvidenceRecord.created_at.asc(), EvidenceRecord.id.asc()]
    return db.query(EvidenceRecord).order_by(*order_clause)


class EvidenceVault:
    """
    Cryptographic Evidence Ledger Manager.
    Appends test execution evidence into an immutable SHA-256 hash chain.
    """

    GENESIS_PREV_HASH = "0" * 64

    @classmethod
    def get_ordered_records(cls, db: Session, desc: bool = False):
        """
        Returns evidence records query strictly ordered by creation timestamp
        and underlying database insertion sequence (rowid on SQLite, id on generic).
        Guarantees deterministic, unambiguous sequential ordering even if multiple
        records share identical timestamps down to the microsecond.
        """
        return _get_ordered_records(db, desc=desc)

    @classmethod
    def commit_evidence(cls, db: Session, test_result: TestResult) -> EvidenceRecord:
        """
        Computes canonical SHA-256 hash, chains to previous record's hash, and commits to database.
        """
        latest_record = cls.get_ordered_records(db, desc=True).first()

        prev_hash = latest_record.payload_sha256 if latest_record else cls.GENESIS_PREV_HASH

        collected_at = ensure_utc(test_result.collected_at or utc_now())
        collected_at_iso = collected_at.isoformat()

        payload_hash = compute_evidence_hash(
            test_id=test_result.test_id,
            collected_at_iso=collected_at_iso,
            result_code=test_result.result_code,
            raw_telemetry=test_result.raw_telemetry
        )

        record = EvidenceRecord(
            test_id=test_result.test_id,
            collected_at=collected_at,
            result_code=test_result.result_code,
            execution_status=test_result.execution_status,
            evidence_provenance=test_result.evidence_provenance,
            raw_telemetry=test_result.raw_telemetry,
            payload_sha256=payload_hash,
            previous_record_hash=prev_hash,
            signature_valid=True
        )

        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @classmethod
    def verify_ledger_integrity(cls, db: Session, up_to_record_id: Optional[str] = None) -> Tuple[bool, List[str]]:
        """
        Verifies that every evidence record's SHA-256 matches its payload and the hash chain is unbroken.
        If up_to_record_id is provided, verifies records from genesis up to and including that record.
        Returns (is_valid, list_of_violations).
        """
        records = _get_ordered_records(db, desc=False).all()

        violations = []
        expected_prev_hash = cls.GENESIS_PREV_HASH

        if not records:
            if up_to_record_id:
                return False, [f"CHECKPOINT TARGET NOT FOUND: Ledger is empty, record '{up_to_record_id}' does not exist."]
            return True, []

        target_found = False
        for idx, record in enumerate(records):
            # 1. Recompute payload hash with guaranteed UTC ISO string
            recomputed_hash = compute_evidence_hash(
                test_id=record.test_id,
                collected_at_iso=ensure_utc(record.collected_at).isoformat(),
                result_code=record.result_code,
                raw_telemetry=record.raw_telemetry
            )

            if recomputed_hash != record.payload_sha256:
                violations.append(
                    f"TAMPER DETECTED: Record #{idx+1} [ID: {record.id}, Test: {record.test_id}] "
                    f"stored digest ({record.payload_sha256[:16]}...) does not match recalculated digest ({recomputed_hash[:16]}...)"
                )

            # 2. Check chain linkage
            if record.previous_record_hash != expected_prev_hash:
                violations.append(
                    f"CHAIN LINKAGE BROKEN: Record #{idx+1} [ID: {record.id}, Test: {record.test_id}] "
                    f"expected previous hash ({expected_prev_hash[:16]}...) but found ({record.previous_record_hash[:16]}...)"
                )

            expected_prev_hash = record.payload_sha256

            if up_to_record_id and record.id == up_to_record_id:
                target_found = True
                break

        if up_to_record_id and not target_found:
            violations.append(f"CHECKPOINT TARGET NOT FOUND: Record '{up_to_record_id}' was not found in evidence ledger.")

        is_valid = len(violations) == 0
        return is_valid, violations

    @classmethod
    def verify_ledger_detailed(cls, db: Session) -> Dict[str, Any]:
        """
        Detailed auditor-oriented audit report including block counts and violation objects.
        """
        records = db.query(EvidenceRecord).order_by(
            EvidenceRecord.created_at.asc(),
            EvidenceRecord.id.asc()
        ).all()

        violations_details = []
        expected_prev_hash = cls.GENESIS_PREV_HASH

        for idx, record in enumerate(records):
            recomputed = compute_evidence_hash(
                test_id=record.test_id,
                collected_at_iso=ensure_utc(record.collected_at).isoformat(),
                result_code=record.result_code,
                raw_telemetry=record.raw_telemetry
            )
            if recomputed != record.payload_sha256:
                violations_details.append({
                    "index": idx + 1,
                    "record_id": record.id,
                    "test_id": record.test_id,
                    "violation_type": "PAYLOAD_TAMPER",
                    "expected_hash": recomputed,
                    "stored_hash": record.payload_sha256
                })

            if record.previous_record_hash != expected_prev_hash:
                violations_details.append({
                    "index": idx + 1,
                    "record_id": record.id,
                    "test_id": record.test_id,
                    "violation_type": "CHAIN_BROKEN",
                    "expected_prev_hash": expected_prev_hash,
                    "stored_prev_hash": record.previous_record_hash
                })

            expected_prev_hash = record.payload_sha256

        return {
            "total_blocks": len(records),
            "is_valid": len(violations_details) == 0,
            "violations_count": len(violations_details),
            "violations": violations_details
        }
