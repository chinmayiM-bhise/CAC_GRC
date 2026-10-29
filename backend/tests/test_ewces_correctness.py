import pytest
import datetime
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.base import utc_now
from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.test_definition import TestDefinition
from app.models.evidence import EvidenceRecord
from app.models.score import EWCESScore
from app.models.finding import Finding
from app.engine.runner.base import TestResult
from app.engine.ledger.vault import EvidenceVault
from app.engine.scoring.classifier import (
    EWCESClassifier,
    STATE_VERIFIED_EFFECTIVE,
    STATE_CONFIG_COMPLIANT_UNVERIFIED,
    STATE_DEFICIENT,
    STATE_UNKNOWN
)
from app.services.finding_service import FindingService


@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def clean_control(db: Session):
    """Fixture generating isolated test controls with mapped test definitions."""
    ctrl_id = "CTRL-STAGE-C-TEST"
    ctrl_other_id = "CTRL-STAGE-C-OTHER"
    t1_id = "TEST-STAGE-C-T1"
    t2_id = "TEST-STAGE-C-T2"
    t1_b_id = "TEST-STAGE-C-T1-B"
    t_opt_id = "TEST-STAGE-C-OPTIONAL"
    t_other_id = "TEST-STAGE-C-OTHER-T1"

    all_ctrls = [ctrl_id, ctrl_other_id]
    all_tests = [t1_id, t2_id, t1_b_id, t_opt_id, t_other_id]

    def _cleanup():
        db.query(Finding).filter(Finding.control_id.in_(all_ctrls)).delete(synchronize_session=False)
        db.query(EWCESScore).filter(EWCESScore.control_id.in_(all_ctrls)).delete(synchronize_session=False)
        db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_(all_tests)).delete(synchronize_session=False)
        db.query(TestDefinition).filter(TestDefinition.test_id.in_(all_tests)).delete(synchronize_session=False)
        db.query(PolicyMapping).filter(PolicyMapping.control_id.in_(all_ctrls)).delete(synchronize_session=False)
        db.query(FrameworkControl).filter(FrameworkControl.control_id.in_(all_ctrls)).delete(synchronize_session=False)
        db.commit()

    _cleanup()

    # Create primary control
    ctrl = FrameworkControl(
        control_id=ctrl_id,
        framework_name="NIST_SP_800_53_R5",
        control_code="SC-99",
        title="Stage C Correctness Test Control",
        description="Evaluates complete coverage and provenance gating.",
        domain_family="SC"
    )
    db.add(ctrl)

    # Create primary mapping
    mapping = PolicyMapping(
        policy_id=1,
        control_id=ctrl_id,
        mapping_status="APPROVED",
        is_ground_truth=True,
        confidence_score=1.0,
        rationale="Exact test mapping"
    )
    db.add(mapping)
    db.flush()

    # Create required Tier 1 test
    t1 = TestDefinition(
        test_id=t1_id,
        mapping_id=mapping.id,
        tier=1,
        is_required=True,
        is_behavioral=False,
        target_type="LINUX_VM",
        name="Tier 1 Static Config",
        description="Inspects config setting.",
        max_ttl_hours=24,
        test_spec={"command": "cat /etc/security/faillock.conf"}
    )
    db.add(t1)

    # Create required Tier 2 behavioral test
    t2 = TestDefinition(
        test_id=t2_id,
        mapping_id=mapping.id,
        tier=2,
        is_required=True,
        is_behavioral=True,
        target_type="LINUX_VM",
        name="Tier 2 Behavioral Probe",
        description="Injects challenge test.",
        max_ttl_hours=24,
        test_spec={"probe_action": "simulate_failed_logins"}
    )
    db.add(t2)
    db.commit()

    yield {
        "control_id": ctrl_id,
        "ctrl_other_id": ctrl_other_id,
        "t1_id": t1_id,
        "t2_id": t2_id,
        "t1_b_id": t1_b_id,
        "t_opt_id": t_opt_id,
        "t_other_id": t_other_id,
        "mapping_id": mapping.id
    }

    _cleanup()


# =============================================================================
# ADVERSARIAL COMBINATION 1: All required checks pass with valid, fresh live evidence
# =============================================================================
def test_1_all_required_checks_pass_with_fresh_live_evidence(db: Session, clean_control):
    """
    Scenario 1: Full required coverage with fresh LIVE_TARGET passes yields VERIFIED_EFFECTIVE.
    """
    c = clean_control
    now = utc_now()

    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_VERIFIED_EFFECTIVE
    assert score.has_tier2_evidence is True
    assert score.hash_integrity_verified is True
    assert score.freshness_score > 0.0


# =============================================================================
# ADVERSARIAL COMBINATION 2: One required Tier 1 check is missing
# =============================================================================
def test_2_one_required_tier1_check_is_missing(db: Session, clean_control):
    """
    Scenario 2: When multiple Tier 1 checks are required and one lacks evidence, state is UNKNOWN.
    """
    c = clean_control
    now = utc_now()

    t1_b = TestDefinition(
        test_id=c["t1_b_id"],
        mapping_id=c["mapping_id"],
        tier=1,
        is_required=True,
        is_behavioral=False,
        target_type="LINUX_VM",
        name="Second Required Config Check",
        description="Must also pass.",
        max_ttl_hours=24,
        test_spec={"command": "cat /etc/ssh/sshd_config"}
    )
    db.add(t1_b)
    db.commit()

    # Only T1 and T2 have evidence; T1-B is missing
    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_UNKNOWN
    assert c["t1_b_id"] in score.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 3: One required Tier 2 check is missing
# =============================================================================
def test_3_one_required_tier2_check_is_missing(db: Session, clean_control):
    """
    Scenario 3: Config passes live, but behavioral challenge test has no evidence.
    State must be CONFIG_COMPLIANT_EFFECTIVENESS_UNVERIFIED, not VERIFIED_EFFECTIVE.
    """
    c = clean_control
    now = utc_now()

    # Only Tier 1 committed
    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_CONFIG_COMPLIANT_UNVERIFIED
    assert score.has_tier2_evidence is False
    assert "behavioral effectiveness testing is absent" in score.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 4: One required check is stale
# =============================================================================
def test_4_one_required_check_is_stale(db: Session, clean_control):
    """
    Scenario 4: Stale evidence (> max_ttl_hours) cannot establish effectiveness.
    """
    c = clean_control
    now = utc_now()
    old_time = now - datetime.timedelta(hours=48)  # max_ttl_hours is 24

    # Sub-case 4A: Tier 1 fresh, Tier 2 stale (> TTL) -> CONFIG_COMPLIANT_UNVERIFIED
    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2_stale = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=old_time)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2_stale)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_CONFIG_COMPLIANT_UNVERIFIED
    assert score.has_tier2_evidence is False

    # Sub-case 4B: Tier 1 stale, Tier 2 fresh -> Config missing/stale forces UNKNOWN
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_([c["t1_id"], c["t2_id"]])).delete()
    db.commit()

    r1_stale = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=old_time)
    r2_fresh = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1_stale)
    EvidenceVault.commit_evidence(db, r2_fresh)

    score_b = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score_b.state == STATE_UNKNOWN
    assert "missing or stale past TTL" in score_b.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 5: Required runner returns an execution error
# =============================================================================
def test_5_required_runner_returns_execution_error(db: Session, clean_control):
    """
    Scenario 5: Runner execution error (result_code = 0) produces UNKNOWN, never DEFICIENT.
    """
    c = clean_control
    now = utc_now()

    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=0, execution_status="EXECUTION_ERROR", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"error": "Binary missing: /usr/sbin/faillock"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_UNKNOWN
    assert score.state != STATE_DEFICIENT
    assert "execution errored" in score.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 6: Target is offline
# =============================================================================
def test_6_target_is_offline_connection_error(db: Session, clean_control):
    """
    Scenario 6: Host unreachable / connection timeout produces UNKNOWN, not DEFICIENT.
    """
    c = clean_control
    now = utc_now()

    r1 = TestResult(test_id=c["t1_id"], result_code=0, execution_status="CONNECTION_ERROR", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"error": "Host 192.168.56.10:22 unreachable: timed out"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=0, execution_status="CONNECTION_ERROR", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"error": "Host 192.168.56.10:22 unreachable: timed out"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_UNKNOWN
    assert score.state != STATE_DEFICIENT
    assert "Target connection failed" in score.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 7: Evidence is simulated but reports a passing result
# =============================================================================
def test_7_simulated_evidence_cannot_establish_verified_effective(db: Session, clean_control):
    """
    Scenario 7: SIMULATED_LAB evidence can NEVER establish VERIFIED_EFFECTIVE.
    """
    c = clean_control
    now = utc_now()

    # Sub-case 7A: Both checks simulated passes
    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SIMULATED", evidence_provenance="SIMULATED_LAB", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SIMULATED", evidence_provenance="SIMULATED_LAB", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score_a = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score_a.state != STATE_VERIFIED_EFFECTIVE
    assert score_a.state == STATE_UNKNOWN
    assert "SIMULATED_LAB" in score_a.diagnostic_summary

    # Sub-case 7B: Tier 1 live pass, Tier 2 simulated pass -> CONFIG_COMPLIANT_UNVERIFIED
    db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_([c["t1_id"], c["t2_id"]])).delete()
    db.commit()

    r1_live = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2_sim = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SIMULATED", evidence_provenance="SIMULATED_LAB", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1_live)
    EvidenceVault.commit_evidence(db, r2_sim)

    score_b = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score_b.state != STATE_VERIFIED_EFFECTIVE
    assert score_b.state == STATE_CONFIG_COMPLIANT_UNVERIFIED
    assert "SIMULATED" in score_b.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 8: Evidence has been tampered with
# =============================================================================
def test_8_evidence_tampering_forces_unknown_and_detects_mismatch(db: Session, clean_control):
    """
    Scenario 8: Post-hoc tampering of raw telemetry causes SHA-256 digest mismatch.
    State must evaluate to UNKNOWN and hash_integrity_verified must be False.
    """
    c = clean_control
    now = utc_now()

    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    ev2 = EvidenceVault.commit_evidence(db, r2)

    # Post-hoc database tampering of telemetry
    ev2.raw_telemetry = {"status": "TAMPERED_PAYLOAD"}
    db.commit()

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_UNKNOWN
    assert score.hash_integrity_verified is False
    assert "Sequential hash-linked ledger integrity compromised" in score.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 9: Conflicting pass and failure evidence exists
# =============================================================================
def test_9_conflicting_pass_and_failure_precedence_is_deficient(db: Session, clean_control):
    """
    Scenario 9: Static config passes (1) but behavioral probe fails (-1).
    Strict precedence dictates DEFICIENT.
    """
    c = clean_control
    now = utc_now()

    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": False}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_DEFICIENT
    assert "Confirmed operational failure" in score.diagnostic_summary


# =============================================================================
# ADVERSARIAL COMBINATION 10: Finding resolution rejected with UNKNOWN assessment
# =============================================================================
def test_10_finding_resolution_rejected_with_unknown_assessment(db: Session, clean_control):
    """
    Scenario 10: Attempting to resolve a finding when control is UNKNOWN raises ValueError.
    """
    c = clean_control
    now = utc_now()

    r1 = TestResult(test_id=c["t1_id"], result_code=0, execution_status="CONNECTION_ERROR", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"error": "offline"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EWCESClassifier.evaluate_control(db, c["control_id"], now=now)

    f = FindingService.sync_finding(db, c["control_id"], c["t1_id"], "HIGH", "Must pass verification")

    with pytest.raises(ValueError) as exc:
        FindingService.update_finding(
            db=db,
            finding_id=f.id,
            status="RESOLVED",
            remediation_notes="Attempted resolution while target assessment is UNKNOWN"
        )
    assert "not VERIFIED_EFFECTIVE" in str(exc.value)


# =============================================================================
# ADVERSARIAL COMBINATION 11: Finding resolution rejected on stale or tampered evidence
# =============================================================================
def test_11_finding_resolution_rejected_on_stale_or_tampered_evidence(db: Session, clean_control):
    """
    Scenario 11: Finding resolution strictly enforces non-zero freshness and intact hash integrity.
    """
    c = clean_control
    f = FindingService.sync_finding(db, c["control_id"], c["t1_id"], "HIGH", "Defect pending fresh pass")

    # Sub-case 11A: Score is VERIFIED_EFFECTIVE but freshness_score = 0.0 (stale)
    stale_score = EWCESScore(
        control_id=c["control_id"],
        state=STATE_VERIFIED_EFFECTIVE,
        freshness_score=0.0,
        has_tier2_evidence=True,
        hash_integrity_verified=True,
        evaluated_at=utc_now(),
        diagnostic_summary="Old pass"
    )
    db.add(stale_score)
    db.commit()

    with pytest.raises(ValueError) as exc_stale:
        FindingService.update_finding(db, f.id, status="RESOLVED", remediation_notes="Attempted closure with stale score")
    assert "expired past its TTL boundary" in str(exc_stale.value)

    # Sub-case 11B: Score is VERIFIED_EFFECTIVE and fresh, but hash_integrity_verified = False (tampered)
    tampered_score = EWCESScore(
        control_id=c["control_id"],
        state=STATE_VERIFIED_EFFECTIVE,
        freshness_score=1.0,
        has_tier2_evidence=True,
        hash_integrity_verified=False,
        evaluated_at=utc_now(),
        diagnostic_summary="Tampered pass"
    )
    db.add(tampered_score)
    db.commit()

    with pytest.raises(ValueError) as exc_tamper:
        FindingService.update_finding(db, f.id, status="RESOLVED", remediation_notes="Attempted closure with tampered ledger")
    assert "failed cryptographic hash integrity verification" in str(exc_tamper.value)


# =============================================================================
# ADVERSARIAL COMBINATION 12: Finding risk-accepted and subsequently reassessed
# =============================================================================
def test_12_finding_risk_accepted_and_subsequent_reassessment(db: Session, clean_control):
    """
    Scenario 12: RISK_ACCEPTED findings remain auditable exceptions during reassessment.
    Does not imply technical remediation (resolved_at = None).
    """
    c = clean_control
    f = FindingService.sync_finding(db, c["control_id"], c["t1_id"], "HIGH", "Unresolvable defect")

    justification = "Accepted by Head of Security due to operational dependency until Q4 patch cycle."
    accepted = FindingService.update_finding(db, f.id, status="RISK_ACCEPTED", remediation_notes=justification)
    assert accepted.status == "RISK_ACCEPTED"
    assert accepted.resolved_at is None
    assert "[RISK ACCEPTED - OPERATIONAL EXCEPTION]" in accepted.remediation_notes

    # Control is reassessed while still failing: finding remains RISK_ACCEPTED
    now = utc_now()
    r1_fail = TestResult(test_id=c["t1_id"], result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=0"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1_fail)
    EWCESClassifier.evaluate_control(db, c["control_id"], now=now)

    f_refreshed = db.query(Finding).filter_by(id=f.id).first()
    assert f_refreshed.status == "RISK_ACCEPTED"
    assert f_refreshed.resolved_at is None

    # Later: defect is fixed on live target and passes all checks
    later = now + datetime.timedelta(seconds=5)
    r1_pass = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=later)
    r2_pass = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=later)
    EvidenceVault.commit_evidence(db, r1_pass)
    EvidenceVault.commit_evidence(db, r2_pass)
    score_pass = EWCESClassifier.evaluate_control(db, c["control_id"], now=later)
    assert score_pass.state == STATE_VERIFIED_EFFECTIVE

    # Now that the control is VERIFIED_EFFECTIVE, user can formally transition to RESOLVED
    resolved = FindingService.update_finding(db, f.id, status="RESOLVED", remediation_notes="Verified resolved post-patch.")
    assert resolved.status == "RESOLVED"
    assert resolved.resolved_at is not None


# =============================================================================
# ADVERSARIAL COMBINATION 13: Optional test is absent while all required tests are valid
# =============================================================================
def test_13_optional_test_absent_allows_verified_effective(db: Session, clean_control):
    """
    Scenario 13: An optional test (is_required = False) without evidence does NOT
    block the control from reaching VERIFIED_EFFECTIVE if all required checks pass live.
    """
    c = clean_control
    now = utc_now()

    # Add optional supporting test
    t_opt = TestDefinition(
        test_id=c["t_opt_id"],
        mapping_id=c["mapping_id"],
        tier=1,
        is_required=False,
        is_behavioral=False,
        target_type="LINUX_VM",
        name="Optional Supporting Telemetry",
        description="Non-blocking optional check.",
        max_ttl_hours=24,
        test_spec={"command": "uptime"}
    )
    db.add(t_opt)
    db.commit()

    # Commit passing evidence for required tests only; optional test has zero evidence
    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state == STATE_VERIFIED_EFFECTIVE
    assert score.has_tier2_evidence is True


# =============================================================================
# ADVERSARIAL COMBINATION 14: Unrelated or duplicated evidence isolation
# =============================================================================
def test_14_unrelated_or_duplicated_evidence_isolation(db: Session, clean_control):
    """
    Scenario 14: Evidence isolation across controls and sequential re-test handling.
    """
    c = clean_control
    now = utc_now()

    # Create secondary control and test definition for unrelated test
    ctrl_other = FrameworkControl(
        control_id=c["ctrl_other_id"],
        framework_name="ISO_27001_2022",
        control_code="A.9.2.1",
        title="Other Control",
        description="Unrelated control.",
        domain_family="A"
    )
    db.add(ctrl_other)
    map_other = PolicyMapping(
        policy_id=1,
        control_id=c["ctrl_other_id"],
        mapping_status="APPROVED",
        is_ground_truth=True,
        confidence_score=1.0,
        rationale="Other mapping"
    )
    db.add(map_other)
    db.flush()

    t_other = TestDefinition(
        test_id=c["t_other_id"],
        mapping_id=map_other.id,
        tier=1,
        is_required=True,
        is_behavioral=False,
        target_type="LINUX_VM",
        name="Unrelated Test",
        description="Belongs to a completely different control.",
        max_ttl_hours=24,
        test_spec={"command": "cat /etc/passwd"}
    )
    db.add(t_other)
    db.commit()

    # Commit failure on the unrelated test
    r_unrelated = TestResult(test_id=c["t_other_id"], result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=5, raw_telemetry={"status": "failed"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r_unrelated)

    # Commit passes for our primary control
    r1 = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    r2 = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)

    score_primary = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score_primary.state == STATE_VERIFIED_EFFECTIVE

    # Sub-case 14B: Sequential re-test on primary control (newest record governs assessment)
    # Commit failure on T1
    r1_fail = TestResult(test_id=c["t1_id"], result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=0"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1_fail)
    score_after_fail = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score_after_fail.state == STATE_DEFICIENT

    # Commit new pass on T1 (remediation verified)
    r1_retest_pass = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1_retest_pass)
    score_after_retest = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score_after_retest.state == STATE_VERIFIED_EFFECTIVE


# =============================================================================
# ADVERSARIAL COMBINATION 15: Stale evidence from prior assessment not silently reused
# =============================================================================
def test_15_stale_evidence_from_prior_assessment_not_silently_reused(db: Session, clean_control):
    """
    Scenario 15: Telemetry collected 72 hours ago (TTL = 24h) evaluates to freshness = 0.0.
    Evaluator classifies control as UNKNOWN, rejecting silent reuse of expired telemetry.
    """
    c = clean_control
    now = utc_now()
    prior_time = now - datetime.timedelta(hours=72)

    r1_old = TestResult(test_id=c["t1_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=prior_time)
    r2_old = TestResult(test_id=c["t2_id"], result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=prior_time)
    EvidenceVault.commit_evidence(db, r1_old)
    EvidenceVault.commit_evidence(db, r2_old)

    score = EWCESClassifier.evaluate_control(db, c["control_id"], now=now)
    assert score.state != STATE_VERIFIED_EFFECTIVE
    assert score.state == STATE_UNKNOWN
    assert score.freshness_score == 0.0
    assert "Required configuration evidence is missing or stale past TTL" in score.diagnostic_summary
