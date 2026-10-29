import pytest
import datetime
from sqlalchemy.orm import Session

from app.database import SessionLocal, Base, engine
from app.models import (
    Policy, FrameworkControl, PolicyMapping, TestDefinition,
    EvidenceRecord, EWCESScore, ChaosDriftRecord, Finding, AssessmentRun
)
from app.models.base import utc_now
from app.engine.orchestrator import TestOrchestrator
from app.engine.ledger.vault import EvidenceVault
from app.engine.ledger.hasher import compute_evidence_hash, canonical_json_dump
from app.engine.scoring.classifier import (
    EWCESClassifier,
    STATE_VERIFIED_EFFECTIVE,
    STATE_CONFIG_COMPLIANT_UNVERIFIED,
    STATE_DEFICIENT,
    STATE_UNKNOWN
)
from app.engine.scoring.decay import calculate_evidence_freshness, ensure_utc
from app.engine.runner.base import TestResult
from app.chaos.mutations import ChaosInjector

@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    yield session
    session.close()

# -------------------------------------------------------------
# 1. DATABASE & SEED INTEGRITY
# -------------------------------------------------------------
def test_database_seed_integrity(db: Session):
    """Verifies that seed data contains policies, framework controls, mappings, and tests."""
    assert db.query(Policy).count() >= 5
    assert db.query(FrameworkControl).count() >= 15
    assert db.query(PolicyMapping).filter_by(is_ground_truth=True).count() >= 10
    assert db.query(TestDefinition).count() >= 10

# -------------------------------------------------------------
# 2. EW-CES FOUR ASSURANCE STATES
# -------------------------------------------------------------
def test_ew_ces_state_verified_effective(db: Session):
    """State 1: VERIFIED_EFFECTIVE when config and behavioral probes pass with fresh evidence."""
    control_id = "NIST-AC-7"
    now = utc_now()
    # Clear prior test evidence for this control
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_(["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"])).delete()
    db.commit()

    r1 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T2", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, control_id, now=now)
    assert score.state == STATE_VERIFIED_EFFECTIVE
    assert score.freshness_score > 0.95
    assert score.hash_integrity_verified is True

def test_ew_ces_state_config_compliant_unverified(db: Session):
    """State 2: CONFIG_COMPLIANT_EFFECTIVENESS_UNVERIFIED when config passes but behavioral probe is absent."""
    control_id = "NIST-AC-7"
    now = utc_now()
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_(["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"])).delete()
    db.commit()

    # Only Tier 1 config check committed
    r1 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)

    score = EWCESClassifier.evaluate_control(db, control_id, now=now)
    assert score.state == STATE_CONFIG_COMPLIANT_UNVERIFIED
    assert "behavioral effectiveness testing is absent" in score.diagnostic_summary

def test_ew_ces_state_deficient_on_confirmed_failure(db: Session):
    """State 3: DEFICIENT when any required check fails, even if another check passes."""
    control_id = "NIST-AC-7"
    now = utc_now()
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_(["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"])).delete()
    db.commit()

    r1 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T2", result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": False}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, control_id, now=now)
    assert score.state == STATE_DEFICIENT
    assert "Confirmed operational failure" in score.diagnostic_summary

def test_ew_ces_state_unknown_on_stale_evidence(db: Session):
    """State 4: UNKNOWN when evidence is older than max TTL."""
    control_id = "NIST-AC-7"
    now = utc_now()
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_(["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"])).delete()
    db.commit()

    r1 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)

    future_time = now + datetime.timedelta(hours=48)
    score = EWCESClassifier.evaluate_control(db, control_id, now=future_time)
    assert score.state == STATE_UNKNOWN
    assert score.freshness_score == 0.0
    assert "missing or stale" in score.diagnostic_summary

# -------------------------------------------------------------
# 3. PRECEDENCE & INTEGRITY RULES
# -------------------------------------------------------------
def test_ew_ces_precedence_integrity_overrules_all(db: Session):
    """Integrity failure overrules everything: tampered evidence forces UNKNOWN."""
    control_id = "NIST-AC-7"
    now = utc_now()
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_(["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"])).delete()
    db.commit()

    r1 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "original"}, collected_at=now)
    rec = EvidenceVault.commit_evidence(db, r1)
    # Directly tamper the raw_telemetry without updating payload_sha256
    rec.raw_telemetry = {"status": "TAMPERED"}
    db.commit()

    score = EWCESClassifier.evaluate_control(db, control_id, now=now)
    assert score.state == STATE_UNKNOWN
    assert score.hash_integrity_verified is False
    assert "Evidence hash mismatch" in score.diagnostic_summary

def test_ew_ces_target_connection_error_is_unknown(db: Session):
    """Target connection error must never be reported as compliant; forces UNKNOWN."""
    control_id = "NIST-AC-7"
    now = utc_now()
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_(["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"])).delete()
    db.commit()

    r1 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=0, execution_status="CONNECTION_ERROR", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"error": "Connection timed out"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)

    score = EWCESClassifier.evaluate_control(db, control_id, now=now)
    assert score.state == STATE_UNKNOWN
    assert "Target connection failed" in score.diagnostic_summary

# -------------------------------------------------------------
# 4. EVIDENCE FRESHNESS & TTL BOUNDARIES
# -------------------------------------------------------------
def test_freshness_exact_boundaries():
    now = utc_now()
    # Exactly fresh (0 hours elapsed)
    assert calculate_evidence_freshness(now, max_ttl_hours=24, now=now) == 1.0
    # Half-life (12 hours elapsed out of 24h)
    half = now - datetime.timedelta(hours=12)
    assert calculate_evidence_freshness(half, max_ttl_hours=24, now=now) == 0.5
    # Exact expiration boundary (24 hours elapsed)
    expired = now - datetime.timedelta(hours=24)
    assert calculate_evidence_freshness(expired, max_ttl_hours=24, now=now) == 0.0
    # Beyond expiration
    past = now - datetime.timedelta(hours=48)
    assert calculate_evidence_freshness(past, max_ttl_hours=24, now=now) == 0.0

def test_freshness_future_dated_evidence():
    now = utc_now()
    # Minor clock skew <= 5 minutes is tolerated
    minor_skew = now + datetime.timedelta(minutes=2)
    assert calculate_evidence_freshness(minor_skew, max_ttl_hours=24, now=now) == 1.0
    # Large forward clock drift is rejected as untrustworthy
    large_drift = now + datetime.timedelta(hours=2)
    assert calculate_evidence_freshness(large_drift, max_ttl_hours=24, now=now) == 0.0

# -------------------------------------------------------------
# 5. EVIDENCE LEDGER TAMPER DETECTION
# -------------------------------------------------------------
def test_evidence_ledger_detects_payload_tampering(db: Session):
    now = utc_now()
    r = TestResult(test_id="TEST-DB-TLS-T1", result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=1, target_type="POSTGRES_DB", duration_ms=10, raw_telemetry={"ssl": "on"}, collected_at=now)
    rec = EvidenceVault.commit_evidence(db, r)

    # Modify telemetry in database
    rec.raw_telemetry = {"ssl": "off"}
    db.commit()

    is_valid, violations = EvidenceVault.verify_ledger_integrity(db)
    assert is_valid is False
    assert any("TAMPER DETECTED" in v for v in violations)

def test_canonical_json_dump_key_order_independence():
    payload1 = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
    payload2 = {"nested": {"x": 10, "y": 20}, "a": 1, "b": 2}
    assert canonical_json_dump(payload1) == canonical_json_dump(payload2)
    h1 = compute_evidence_hash("TEST-1", "2026-10-20T10:00:00Z", 1, payload1)
    h2 = compute_evidence_hash("TEST-1", "2026-10-20T10:00:00Z", 1, payload2)
    assert h1 == h2

# -------------------------------------------------------------
# 6. CHAOS ENGINE PERSISTENCE & VERIFICATION
# -------------------------------------------------------------
def test_chaos_drift_persistence_in_database(db: Session):
    """Verifies that drift state is committed to DB and survives across calls."""
    ChaosInjector.restore_baseline(actor="PYTEST")
    active_before = ChaosInjector.list_active_drifts()
    assert len(active_before) == 0

    res = ChaosInjector.inject_drift("pam-lockout-bypass", mode="SIMULATED", actor="PYTEST")
    assert res["status"] == "DRIFT_INJECTED"

    # Query DB directly to verify persistence
    record = db.query(ChaosDriftRecord).filter_by(drift_id="pam-lockout-bypass", status="ACTIVE").first()
    assert record is not None
    assert record.drift_type == "SIMULATED"

    # Clean up
    restore_res = ChaosInjector.restore_baseline(actor="PYTEST")
    assert restore_res["cleared_drifts_count"] >= 1
    record_after = db.query(ChaosDriftRecord).filter_by(drift_id="pam-lockout-bypass", status="ACTIVE").first()
    assert record_after is None

def test_chaos_live_mutation_fails_safely_when_target_offline():
    """Live mutation must raise ConnectionError if target is unreachable, never faking success."""
    with pytest.raises(ConnectionError) as exc_info:
        ChaosInjector.inject_drift("pam-lockout-bypass", mode="LIVE_LAB_MUTATION", actor="PYTEST")
    assert "Target LINUX_VM unreachable" in str(exc_info.value)

# -------------------------------------------------------------
# 7. FINDINGS & REMEDIATION LIFECYCLE
# -------------------------------------------------------------
def test_finding_lifecycle_auto_sync_and_resolution(db: Session):
    control_id = "NIST-AC-7"
    now = utc_now()

    # 1. Trigger failure -> Finding automatically created
    r_fail = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=999"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r_fail)
    EWCESClassifier.evaluate_control(db, control_id, now=now)

    finding = db.query(Finding).filter_by(control_id=control_id, status="OPEN").first()
    assert finding is not None
    assert finding.severity == "HIGH"

    # 2. Trigger passing checks -> Finding automatically resolved
    r_pass1 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T1", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r_pass2 = TestResult(test_id="TEST-VM-PAM-LOCKOUT-T2", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r_pass1)
    EvidenceVault.commit_evidence(db, r_pass2)
    EWCESClassifier.evaluate_control(db, control_id, now=now)

    finding_resolved = db.query(Finding).filter_by(control_id=control_id).order_by(Finding.created_at.desc()).first()
    assert finding_resolved.status == "RESOLVED"
    assert finding_resolved.resolved_at is not None
