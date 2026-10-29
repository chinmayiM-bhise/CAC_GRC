import pytest
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.base import utc_now
from app.models.framework import FrameworkControl
from app.models.score import EWCESScore
from app.models.finding import Finding
from app.models.evidence import EvidenceRecord
from app.engine.scoring.classifier import (
    STATE_DEFICIENT,
    STATE_VERIFIED_EFFECTIVE,
    STATE_CONFIG_COMPLIANT_UNVERIFIED,
    STATE_UNKNOWN
)
from app.engine.runner.base import TestResult
from app.engine.ledger.vault import EvidenceVault

from app.services.assurance_service import AssuranceService
from app.services.finding_service import FindingService
from app.services.ledger_service import LedgerService
from app.services.asset_service import AssetService

@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    yield session
    session.close()

def test_assurance_overview_consistency(db: Session):
    """
    Validates that AssuranceService computes strictly consistent arithmetic:
    sum of all 4 states equals total controls, and assurance index is mathematically sound.
    """
    overview = AssuranceService.get_assurance_overview(db)
    ctrls = overview["controls"]

    total = ctrls["total"]
    ve = ctrls["verified_effective"]
    cc = ctrls["config_compliant_unverified"]
    df = ctrls["deficient"]
    unk = ctrls["unknown"]

    assert total > 0
    assert ve + cc + df + unk == total
    expected_index = round((ve / total) * 100, 1)
    assert ctrls["assurance_index_pct"] == expected_index

    # Check findings breakdown
    findings_total = overview["findings"]["total_open"]
    by_sev = overview["findings"]["by_severity"]
    assert sum(by_sev.values()) == findings_total

    # Check evidence consistency
    assert overview["evidence"]["total_records"] >= 0
    assert 0.0 <= overview["evidence"]["average_freshness"] <= 1.0

def test_finding_service_deduplication(db: Session):
    """
    Validates that FindingService.sync_finding deduplicates active findings for the same control.
    """
    test_control = "TEST-CTRL-DEDUP-01"
    t_id = "TEST-DEDUP-T1"

    # Clean up prior test findings
    db.query(Finding).filter_by(control_id=test_control).delete()
    db.commit()

    # First trigger: creates new OPEN finding
    f1 = FindingService.sync_finding(
        db=db,
        control_id=test_control,
        test_id=t_id,
        severity="HIGH",
        description="Initial failure detection"
    )
    assert f1.id is not None
    assert f1.status == "OPEN"
    initial_id = f1.id

    # Second trigger for same control while finding is OPEN: must update, NOT create duplicate
    f2 = FindingService.sync_finding(
        db=db,
        control_id=test_control,
        test_id=t_id,
        severity="CRITICAL",
        description="Updated recurring failure"
    )
    assert f2.id == initial_id
    assert f2.severity == "CRITICAL"
    assert f2.description == "Updated recurring failure"

    # Count total findings for this control in DB
    count = db.query(Finding).filter_by(control_id=test_control).count()
    assert count == 1

def test_finding_resolution_requires_passing_assessment(db: Session):
    """
    Validates that a technical finding CANNOT be resolved while the underlying control is DEFICIENT.
    """
    test_control = "TEST-CTRL-RESOLVE-GATE"
    t_id = "TEST-RESOLVE-T1"
    now = utc_now()

    # Clean up
    db.query(Finding).filter_by(control_id=test_control).delete()
    db.query(EWCESScore).filter_by(control_id=test_control).delete()
    db.commit()

    # Create DEFICIENT score
    score = EWCESScore(
        control_id=test_control,
        state=STATE_DEFICIENT,
        freshness_score=1.0,
        has_tier2_evidence=False,
        hash_integrity_verified=True,
        evaluated_at=now,
        diagnostic_summary="Confirmed failure."
    )
    db.add(score)

    # Create OPEN finding
    finding = FindingService.sync_finding(
        db=db,
        control_id=test_control,
        test_id=t_id,
        severity="HIGH",
        description="Must pass retest before closing"
    )

    # Attempt to resolve finding directly: should raise ValueError
    with pytest.raises(ValueError) as excinfo:
        FindingService.update_finding(
            db=db,
            finding_id=finding.id,
            status="RESOLVED",
            remediation_notes="Attempted manual resolution"
        )
    assert "currently DEFICIENT" in str(excinfo.value)
    assert "passing re-assessment is required" in str(excinfo.value)

    # Now simulate passing re-assessment
    score_pass = EWCESScore(
        control_id=test_control,
        state=STATE_VERIFIED_EFFECTIVE,
        freshness_score=1.0,
        has_tier2_evidence=True,
        hash_integrity_verified=True,
        evaluated_at=utc_now(),
        diagnostic_summary="All checks passed."
    )
    db.add(score_pass)
    db.commit()

    # Now resolving must succeed
    updated = FindingService.update_finding(
        db=db,
        finding_id=finding.id,
        status="RESOLVED",
        remediation_notes="Remediation verified by automated test pass"
    )
    assert updated.status == "RESOLVED"
    assert updated.resolved_at is not None

def test_asset_service_data_separation_and_credential_sanitization(db: Session):
    """
    Validates that AssetService lists assets with network reachability,
    historical evidence counts, and strictly zero leaked credentials.
    """
    assets = AssetService.list_monitored_assets(db)
    # Core scope strictly limited to Linux SSH and PostgreSQL (Git/Gitea removed)
    assert len(assets) == 2
    asset_types = {a["type"] for a in assets}
    assert asset_types == {"LINUX_VM", "POSTGRES_DB"}

    for asset in assets:
        # Check required fields
        assert "id" in asset
        assert "name" in asset
        assert "type" in asset
        assert "current_connectivity" in asset
        assert asset["current_connectivity"] in ("ONLINE", "OFFLINE")
        assert "historical_evidence_count" in asset
        assert isinstance(asset["historical_evidence_count"], int)

        # Check credential sanitization
        assert "password" not in asset
        assert "secret" not in asset
        assert "token" not in asset
        assert "private_key" not in asset
        assert "credentials" not in asset
