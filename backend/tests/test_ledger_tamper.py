import pytest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.database import Base
from app.models.evidence import EvidenceRecord
from app.models.base import utc_now
from app.engine.ledger.vault import EvidenceVault
from app.engine.runner.base import TestResult
from app.engine.scoring.decay import ensure_utc

@pytest.fixture
def clean_ledger_db():
    """Provides an isolated in-memory database session with clean sequential evidence records."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestSession()
    yield session
    session.close()
    engine.dispose()

def test_empty_ledger_is_valid(clean_ledger_db: Session):
    """Condition 1: An empty ledger returns is_valid=True and 0 violations."""
    is_valid, violations = EvidenceVault.verify_ledger_integrity(clean_ledger_db)
    assert is_valid is True
    assert violations == []

def test_genesis_block_creation_and_hash(clean_ledger_db: Session):
    """Condition 2: Genesis block uses 64 zeros as previous hash and validates cleanly."""
    now = utc_now()
    r = TestResult(
        test_id="TEST-LEDGER-GENESIS",
        result_code=1,
        execution_status="SUCCESS",
        evidence_provenance="SIMULATED_LAB",
        tier=1,
        target_type="LINUX_VM",
        duration_ms=12,
        raw_telemetry={"status": "genesis"},
        collected_at=now
    )
    record = EvidenceVault.commit_evidence(clean_ledger_db, r)
    assert record.id is not None
    assert record.payload_sha256 is not None
    assert len(record.payload_sha256) == 64

def test_payload_tampering_detected(clean_ledger_db: Session):
    """Condition 3: Tampering with raw telemetry is detected with exact index and record ID."""
    now = utc_now()
    r = TestResult(
        test_id="TEST-LEDGER-TAMPER-01",
        result_code=1,
        execution_status="SUCCESS",
        evidence_provenance="SIMULATED_LAB",
        tier=1,
        target_type="LINUX_VM",
        duration_ms=10,
        raw_telemetry={"setting": "authorized_value"},
        collected_at=now
    )
    rec = EvidenceVault.commit_evidence(clean_ledger_db, r)
    rec_id = rec.id

    # Post-hoc tampering of raw telemetry in database
    rec.raw_telemetry = {"setting": "MALICIOUSLY_MUTATED_VALUE"}
    clean_ledger_db.commit()

    is_valid, violations = EvidenceVault.verify_ledger_integrity(clean_ledger_db)
    assert is_valid is False
    assert any(rec_id in v and "TAMPER DETECTED" in v for v in violations)

    # Verify structured audit report
    detailed = EvidenceVault.verify_ledger_detailed(clean_ledger_db)
    assert detailed["is_valid"] is False
    tamper_violations = [v for v in detailed["violations"] if v.get("record_id") == rec_id]
    assert len(tamper_violations) >= 1
    assert tamper_violations[0]["violation_type"] == "PAYLOAD_TAMPER"

def test_broken_prev_hash_link_detected(clean_ledger_db: Session):
    """Condition 4: Explicit tampering with previous_record_hash breaks chain linkage."""
    now = utc_now()
    r1 = TestResult(
        test_id="TEST-LEDGER-CHAIN-A",
        result_code=1,
        execution_status="SUCCESS",
        evidence_provenance="SIMULATED_LAB",
        tier=1,
        target_type="LINUX_VM",
        duration_ms=5,
        raw_telemetry={"step": "A"},
        collected_at=now
    )
    r2 = TestResult(
        test_id="TEST-LEDGER-CHAIN-B",
        result_code=1,
        execution_status="SUCCESS",
        evidence_provenance="SIMULATED_LAB",
        tier=1,
        target_type="LINUX_VM",
        duration_ms=8,
        raw_telemetry={"step": "B"},
        collected_at=now + datetime.timedelta(seconds=1)
    )
    rec1 = EvidenceVault.commit_evidence(clean_ledger_db, r1)
    rec2 = EvidenceVault.commit_evidence(clean_ledger_db, r2)

    # Tamper with chain link
    rec2.previous_record_hash = "f" * 64
    clean_ledger_db.commit()

    is_valid, violations = EvidenceVault.verify_ledger_integrity(clean_ledger_db)
    assert is_valid is False
    assert any("CHAIN LINKAGE BROKEN" in v and rec2.id in v for v in violations)

def test_intermediate_record_deletion_breaks_chain(clean_ledger_db: Session):
    """Condition 5: Deleting an intermediate block breaks the chain linkage of successor block."""
    now = utc_now()
    r1 = TestResult(test_id="TEST-LEDGER-DEL-1", result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=1, target_type="LINUX_VM", duration_ms=5, raw_telemetry={"k": 1}, collected_at=now)
    r2 = TestResult(test_id="TEST-LEDGER-DEL-2", result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=1, target_type="LINUX_VM", duration_ms=5, raw_telemetry={"k": 2}, collected_at=now + datetime.timedelta(seconds=1))
    r3 = TestResult(test_id="TEST-LEDGER-DEL-3", result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=1, target_type="LINUX_VM", duration_ms=5, raw_telemetry={"k": 3}, collected_at=now + datetime.timedelta(seconds=2))

    rec1 = EvidenceVault.commit_evidence(clean_ledger_db, r1)
    rec2 = EvidenceVault.commit_evidence(clean_ledger_db, r2)
    rec3 = EvidenceVault.commit_evidence(clean_ledger_db, r3)

    # Delete intermediate record 2
    clean_ledger_db.delete(rec2)
    clean_ledger_db.commit()

    # rec3 now expects rec2's hash, but previous block is rec1
    is_valid, violations = EvidenceVault.verify_ledger_integrity(clean_ledger_db)
    assert is_valid is False
    assert any("CHAIN LINKAGE BROKEN" in v and rec3.id in v for v in violations)

def test_database_persistence_and_reload(tmp_path):
    """Condition 6: Committing evidence in one session and reading in a new session preserves valid chain."""
    db_file = tmp_path / "reload_test.db"
    test_engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    s1 = TestSession()

    now = utc_now()
    r1 = TestResult(test_id="TEST-LEDGER-RELOAD-1", result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=1, target_type="LINUX_VM", duration_ms=5, raw_telemetry={"r": 1}, collected_at=now)
    r2 = TestResult(test_id="TEST-LEDGER-RELOAD-2", result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=1, target_type="LINUX_VM", duration_ms=5, raw_telemetry={"r": 2}, collected_at=now + datetime.timedelta(seconds=1))
    EvidenceVault.commit_evidence(s1, r1)
    EvidenceVault.commit_evidence(s1, r2)
    s1.close()

    # Open completely new session
    s2 = TestSession()
    try:
        rec1 = s2.query(EvidenceRecord).filter_by(test_id="TEST-LEDGER-RELOAD-1").first()
        rec2 = s2.query(EvidenceRecord).filter_by(test_id="TEST-LEDGER-RELOAD-2").first()
        assert rec1 is not None
        assert rec2 is not None
        assert rec2.previous_record_hash == rec1.payload_sha256
    finally:
        s2.close()
        test_engine.dispose()
