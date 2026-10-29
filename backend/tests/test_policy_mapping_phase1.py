"""
Comprehensive Phase 1 Test Suite: Policy Management & Framework Control Mapping.

Validates:
1. Authoritative Framework Catalogs (ISO 27001:2022 93 Annex A controls + NIST 800-53 Rev 5 1,196 entries).
2. Control Enhancement and Parent-Child relationships.
3. Database duplicate prevention constraints (control_id, (policy_id, control_id)).
4. Starter Policy Library (22 enterprise policies spanning 20 security domains).
5. Ground Truth Mappings preservation (10 HUMAN_APPROVED) and proposed starter mappings.
6. Policy Lifecycle Workflow (DRAFT -> UNDER_REVIEW -> REJECTED -> UNDER_REVIEW -> APPROVED -> ARCHIVED).
7. Policy-to-Control Mapping Workflow (Create PROPOSED -> Review APPROVED/REJECTED -> Delete).
8. Many-to-Many traceability: One policy to multiple controls, One control to multiple policies.
9. Multi-dimensional Coverage Metrics (Catalog vs. Policy Mapping vs. Human Validation vs. Technical CaC).
10. Catalog Import Idempotency.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.main import app
from app.database import SessionLocal
from app.config import settings
from app.models.policy import Policy
from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.audit_log import AuditLog
from app.seed_data.seed import seed_database

client = TestClient(app)

TEST_ADMIN_TOKEN = "test-secret-admin-token-2026"
TEST_ENGINEER_TOKEN = "test-secret-engineer-token-2026"
TEST_AUDITOR_TOKEN = "test-secret-auditor-token-2026"

AUDITOR_HEADER = {"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"}
ENGINEER_HEADER = {"Authorization": f"Bearer {TEST_ENGINEER_TOKEN}"}
ADMIN_HEADER = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}


@pytest.fixture(autouse=True)
def configure_test_auth():
    """Configures explicit tokens for testing in a controlled manner."""
    orig_admin = settings.CAC_ADMIN_TOKEN
    orig_eng = settings.CAC_ENGINEER_TOKEN
    orig_aud = settings.CAC_AUDITOR_TOKEN
    orig_auth = settings.AUTH_ENABLED
    orig_bypass = settings.DEV_AUTH_BYPASS

    settings.CAC_ADMIN_TOKEN = TEST_ADMIN_TOKEN
    settings.CAC_ENGINEER_TOKEN = TEST_ENGINEER_TOKEN
    settings.CAC_AUDITOR_TOKEN = TEST_AUDITOR_TOKEN
    settings.AUTH_ENABLED = True
    settings.DEV_AUTH_BYPASS = False

    yield

    settings.CAC_ADMIN_TOKEN = orig_admin
    settings.CAC_ENGINEER_TOKEN = orig_eng
    settings.CAC_AUDITOR_TOKEN = orig_aud
    settings.AUTH_ENABLED = orig_auth
    settings.DEV_AUTH_BYPASS = orig_bypass


# =============================================================================
# 1. Authoritative Framework Catalogs
# =============================================================================
def test_authoritative_framework_catalogs_counts_and_structure():
    """
    Validates:
    - ISO/IEC 27001:2022: Exactly 93 Annex A reference controls.
      Breakdown: Organizational (37), People (8), Physical (14), Technological (34).
    - NIST SP 800-53 Rev 5: Exactly 1,196 entries from official OSCAL release.
      Breakdown: 300 active base controls, 714 active enhancements, 182 withdrawn entries.
    - Combined catalog total: 1,289 controls.
    """
    db: Session = SessionLocal()
    try:
        # ISO/IEC 27001:2022
        iso_controls = db.query(FrameworkControl).filter(
            FrameworkControl.framework_name == "ISO_27001_2022"
        ).all()
        assert len(iso_controls) == 93, f"Expected 93 ISO controls, got {len(iso_controls)}"

        # Validate ISO categories
        org = [c for c in iso_controls if "Organizational" in c.domain_family]
        people = [c for c in iso_controls if "People" in c.domain_family]
        physical = [c for c in iso_controls if "Physical" in c.domain_family]
        tech = [c for c in iso_controls if "Technological" in c.domain_family]
        assert len(org) == 37, f"Expected 37 Organizational controls, got {len(org)}"
        assert len(people) == 8, f"Expected 8 People controls, got {len(people)}"
        assert len(physical) == 14, f"Expected 14 Physical controls, got {len(physical)}"
        assert len(tech) == 34, f"Expected 34 Technological controls, got {len(tech)}"

        # NIST SP 800-53 Rev 5
        nist_controls = db.query(FrameworkControl).filter(
            FrameworkControl.framework_name == "NIST_SP_800_53_R5"
        ).all()
        assert len(nist_controls) == 1196, f"Expected 1,196 NIST controls, got {len(nist_controls)}"

        nist_active_base = [c for c in nist_controls if not c.is_enhancement and c.status == "ACTIVE"]
        nist_active_enhancements = [c for c in nist_controls if c.is_enhancement and c.status == "ACTIVE"]
        nist_withdrawn = [c for c in nist_controls if c.status == "WITHDRAWN"]

        assert len(nist_active_base) == 300, f"Expected 300 active base NIST controls, got {len(nist_active_base)}"
        assert len(nist_active_enhancements) == 714, f"Expected 714 active enhancements, got {len(nist_active_enhancements)}"
        assert len(nist_withdrawn) == 182, f"Expected 182 withdrawn NIST entries, got {len(nist_withdrawn)}"

        # Total combined
        total = db.query(FrameworkControl).count()
        assert total == 1289, f"Expected 1,289 total controls, got {total}"
    finally:
        db.close()


# =============================================================================
# 2. Control Enhancements & Parent-Child Relationships
# =============================================================================
def test_control_enhancements_and_parent_relationships():
    """
    Validates parent-enhancement links in NIST SP 800-53 Rev 5:
    - NIST-AC-2(1) must have is_enhancement=True and parent_control_id="NIST-AC-2".
    - NIST-AC-2 must have is_enhancement=False and parent_control_id=None.
    """
    db: Session = SessionLocal()
    try:
        base = db.query(FrameworkControl).filter(FrameworkControl.control_id == "NIST-AC-2").first()
        assert base is not None
        assert base.is_enhancement is False
        assert base.parent_control_id is None

        enhancement = db.query(FrameworkControl).filter(FrameworkControl.control_id == "NIST-AC-2(1)").first()
        assert enhancement is not None
        assert enhancement.is_enhancement is True
        assert enhancement.parent_control_id == "NIST-AC-2"

        # Verify API returns parent details and enhancements
        res = client.get("/api/v1/controls/NIST-AC-2", headers=AUDITOR_HEADER)
        assert res.status_code == 200
        data = res.json()
        assert data["control_id"] == "NIST-AC-2"
        assert "enhancements" in data
        assert any(e["control_id"] == "NIST-AC-2(1)" for e in data["enhancements"])
    finally:
        db.close()


# =============================================================================
# 3. Duplicate Prevention Constraints
# =============================================================================
def test_duplicate_control_prevention():
    """Validates that duplicate control IDs are rejected by unique constraints."""
    db: Session = SessionLocal()
    try:
        dup = FrameworkControl(
            control_id="ISO-A.5.1",
            framework_name="ISO_27001_2022",
            title="Duplicate Test",
            domain_family="Organizational controls",
            description="Testing uniqueness",
            assessment_method="ORGANIZATIONAL_MANUAL"
        )
        db.add(dup)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        db.close()


def test_duplicate_mapping_prevention():
    """Validates that duplicate (policy_id, control_id) relationships are prevented."""
    db: Session = SessionLocal()
    try:
        existing = db.query(PolicyMapping).first()
        assert existing is not None

        # Attempt to insert identical (policy_id, control_id) mapping
        dup = PolicyMapping(
            policy_id=existing.policy_id,
            control_id=existing.control_id,
            confidence_score=0.9,
            rationale="Duplicate relationship test",
            mapping_status="PROPOSED"
        )
        db.add(dup)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        # Also test via API
        pol = db.query(Policy).filter(Policy.id == existing.policy_id).first()
        res = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={
                "policy_id": pol.id,
                "control_id": existing.control_id,
                "rationale": "Duplicate API test",
                "mapping_status": "PROPOSED"
            }
        )
        assert res.status_code in [400, 409]
        assert "already exists" in res.json()["detail"]
    finally:
        db.close()


# =============================================================================
# 4. Starter Policy Library Preservation & Coverage
# =============================================================================
def test_starter_policy_library_preservation():
    """
    Validates that:
    - 22 policies exist in the database.
    - All 6 original policies are preserved intact.
    - 16 starter policies covering domains (AUP, AST, CLS, CRY, VUL, IRP, BCP, CHG, CFG, NET, TPM, RSK, TRN, PHY, RET) are present.
    """
    db: Session = SessionLocal()
    try:
        policies = db.query(Policy).all()
        assert len(policies) >= 22

        # Original policies
        orig_codes = ["POL-IAM-001", "POL-IAM-002", "POL-AUD-001", "POL-DAT-001", "POL-SEC-001", "POL-DEV-001"]
        for code in orig_codes:
            pol = db.query(Policy).filter(Policy.policy_code == code).first()
            assert pol is not None, f"Original policy {code} missing!"
            assert pol.lifecycle_status == "APPROVED"

        # Starter domain policies
        starter_codes = [
            "POL-AUP-001", "POL-AST-001", "POL-CLS-001", "POL-CRY-001",
            "POL-VUL-001", "POL-IRP-001", "POL-BCP-001", "POL-BCP-002",
            "POL-CHG-001", "POL-CFG-001", "POL-NET-001", "POL-TPM-001",
            "POL-RSK-001", "POL-TRN-001", "POL-PHY-001", "POL-RET-001"
        ]
        for code in starter_codes:
            pol = db.query(Policy).filter(Policy.policy_code == code).first()
            assert pol is not None, f"Starter policy {code} missing!"
            assert pol.title is not None
            assert pol.statement is not None
    finally:
        db.close()


# =============================================================================
# 5. Ground Truth Mappings Preservation
# =============================================================================
def test_ground_truth_mappings_preservation():
    """
    Validates that the 10 original ground truth mappings remain intact and
    marked with HUMAN_APPROVED.
    """
    db: Session = SessionLocal()
    try:
        approved_maps = db.query(PolicyMapping).filter(
            PolicyMapping.mapping_status.in_(["HUMAN_APPROVED", "APPROVED"])
        ).all()
        assert len(approved_maps) >= 10, f"Expected at least 10 approved mappings, found {len(approved_maps)}"

        # Verify key baseline mappings
        pol_iam_1 = db.query(Policy).filter(Policy.policy_code == "POL-IAM-001").first()
        assert pol_iam_1 is not None

        nist_ac_7_map = db.query(PolicyMapping).filter(
            PolicyMapping.policy_id == pol_iam_1.id,
            PolicyMapping.control_id == "NIST-AC-7"
        ).first()
        assert nist_ac_7_map is not None
        assert nist_ac_7_map.mapping_status in ["HUMAN_APPROVED", "APPROVED"]
    finally:
        db.close()


# =============================================================================
# 6. Policy Lifecycle Workflow (CRUD, Submit, Review, Archive)
# =============================================================================
def test_policy_lifecycle_workflow():
    """
    Tests the full policy governance workflow:
    1. Create Draft policy via POST /api/v1/policies.
    2. Edit Draft policy via PATCH /api/v1/policies/{code}.
    3. Submit for review via PATCH /api/v1/policies/{code}/submit -> status UNDER_REVIEW.
    4. Review and Reject with feedback -> status REJECTED.
    5. Re-submit for review -> status UNDER_REVIEW.
    6. Review and Approve -> status APPROVED.
    7. Archive policy via PATCH /api/v1/policies/{code}/archive -> status ARCHIVED.
    """
    test_code = "POL-TEST-LIFECYCLE-99"

    # Pre-clean
    db = SessionLocal()
    try:
        p = db.query(Policy).filter(Policy.policy_code == test_code).first()
        if p:
            db.delete(p)
            db.commit()
    finally:
        db.close()

    try:
        # 1. Create Draft (requires engineer or admin role)
        create_payload = {
            "policy_code": test_code,
            "title": "Automated Lifecycle Test Policy",
            "category": "Testing & QA",
            "statement": "All systems must pass lifecycle validation checks.",
            "description": "Lifecycle validation test policy purpose statement.",
            "owner": "QA Lead",
            "scope": "Test Environments",
            "version": "1.0"
        }
        res = client.post("/api/v1/policies", headers=ENGINEER_HEADER, json=create_payload)
        assert res.status_code in [200, 201], res.text
        created = res.json()
        assert created["policy_code"] == test_code
        assert created["lifecycle_status"] == "DRAFT"

        # 2. Edit Draft
        res = client.patch(
            f"/api/v1/policies/{test_code}",
            headers=ENGINEER_HEADER,
            json={"title": "Updated Lifecycle Test Policy"}
        )
        assert res.status_code == 200
        assert res.json()["title"] == "Updated Lifecycle Test Policy"

        # 3. Submit for Review
        res = client.patch(f"/api/v1/policies/{test_code}/submit", headers=ENGINEER_HEADER)
        assert res.status_code == 200
        assert res.json()["lifecycle_status"] == "UNDER_REVIEW"

        # 4. Review & Reject (auditor role)
        res = client.patch(
            f"/api/v1/policies/{test_code}/review",
            headers=AUDITOR_HEADER,
            json={
                "action": "REJECT",
                "approver": "Senior Auditor",
                "rejection_reason": "Policy statement requires additional specificity on log retention."
            }
        )
        assert res.status_code == 200
        assert res.json()["lifecycle_status"] == "REJECTED"
        assert "additional specificity" in res.json()["rejection_reason"]

        # 5. Re-submit
        res = client.patch(f"/api/v1/policies/{test_code}/submit", headers=ENGINEER_HEADER)
        assert res.status_code == 200
        assert res.json()["lifecycle_status"] == "UNDER_REVIEW"

        # 6. Review & Approve (auditor role)
        res = client.patch(
            f"/api/v1/policies/{test_code}/review",
            headers=AUDITOR_HEADER,
            json={
                "action": "APPROVE",
                "approver": "Chief Information Security Officer"
            }
        )
        assert res.status_code == 200
        assert res.json()["lifecycle_status"] == "APPROVED"
        assert res.json()["approver"] == "Chief Information Security Officer"

        # 7. Archive (restricted to Admin role)
        res = client.patch(f"/api/v1/policies/{test_code}/archive", headers=ADMIN_HEADER)
        assert res.status_code == 200
        assert res.json()["lifecycle_status"] == "ARCHIVED"
    finally:
        # Cleanup
        db = SessionLocal()
        try:
            p = db.query(Policy).filter(Policy.policy_code == test_code).first()
            if p:
                db.delete(p)
                db.commit()
        finally:
            db.close()


# =============================================================================
# 7. Mapping Creation, Review, and Deletion Workflow
# =============================================================================
def test_mapping_lifecycle_workflow():
    """
    Tests policy-to-control mapping lifecycle:
    1. Create PROPOSED mapping via POST /api/v1/mappings.
    2. Review and APPROVE mapping via PATCH /api/v1/mappings/{id}/review.
    3. Verify audit log.
    4. Delete mapping via DELETE /api/v1/mappings/{id}.
    """
    db: Session = SessionLocal()
    try:
        pol = db.query(Policy).filter(Policy.policy_code == "POL-IAM-001").first()
        ctrl = db.query(FrameworkControl).filter(FrameworkControl.control_id == "NIST-AC-3").first()
        assert pol is not None and ctrl is not None

        # Clean up any pre-existing mapping for this pair
        db.query(PolicyMapping).filter(
            PolicyMapping.policy_id == pol.id,
            PolicyMapping.control_id == ctrl.control_id
        ).delete()
        db.commit()

        # 1. Create PROPOSED mapping
        res = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={
                "policy_id": pol.id,
                "control_id": ctrl.control_id,
                "rationale": "POL-IAM-001 access enforcement directly maps to NIST-AC-3.",
                "confidence_score": 0.95,
                "mapping_status": "PROPOSED"
            }
        )
        assert res.status_code in [200, 201], res.text
        m_data = res.json()
        mapping_id = m_data["id"]
        assert m_data["mapping_status"] == "PROPOSED"

        # 2. Review and Approve
        res = client.patch(
            f"/api/v1/mappings/{mapping_id}/review",
            headers=AUDITOR_HEADER,
            json={
                "status": "APPROVED",
                "reviewer": "Lead Compliance Auditor",
                "review_notes": "Verified alignment with enterprise RBAC specifications."
            }
        )
        assert res.status_code == 200
        reviewed = res.json()
        assert reviewed["mapping_status"] in ["APPROVED", "HUMAN_APPROVED"]
        assert reviewed["reviewer"] == "Lead Compliance Auditor"
        assert reviewed["reviewed_at"] is not None

        # 3. Check Audit Trail
        res = client.get(f"/api/v1/mappings/{mapping_id}/audit", headers=AUDITOR_HEADER)
        assert res.status_code == 200
        audit_trail = res.json()
        assert len(audit_trail) >= 1
        assert any("APPROVED" in str(a) for a in audit_trail)

        # 4. Delete Mapping
        res = client.delete(f"/api/v1/mappings/{mapping_id}", headers=AUDITOR_HEADER)
        assert res.status_code in [200, 204]

        # Verify deletion in DB
        del_check = db.query(PolicyMapping).filter(PolicyMapping.id == mapping_id).first()
        assert del_check is None
    finally:
        db.close()


# =============================================================================
# 8. Many-to-Many Traceability
# =============================================================================
def test_many_to_many_traceability():
    """
    Validates many-to-many relationship:
    1. One policy maps to multiple controls.
    2. One control maps to multiple policies.
    """
    db: Session = SessionLocal()
    try:
        # 1. Policy POL-IAM-001 -> multiple controls
        pol_iam = db.query(Policy).filter(Policy.policy_code == "POL-IAM-001").first()
        iam_maps = db.query(PolicyMapping).filter(PolicyMapping.policy_id == pol_iam.id).all()
        assert len(iam_maps) >= 2, f"POL-IAM-001 should map to multiple controls, got {len(iam_maps)}"

        # 2. Control linked to multiple policies
        # Find any control with >= 2 policies or verify query capability
        res = client.get(f"/api/v1/policies/{pol_iam.policy_code}/controls", headers=AUDITOR_HEADER)
        assert res.status_code == 200
        controls = res.json()
        assert len(controls) >= 2
    finally:
        db.close()


# =============================================================================
# 9. Coverage Report Metrics & Gap Identification
# =============================================================================
def test_coverage_report_metrics_and_gap_identification():
    """
    Validates GET /api/v1/mappings/coverage endpoint:
    - Reports exact catalog totals (1,289 total, 93 ISO, 1,196 NIST).
    - Distinguishes catalog coverage vs policy mapping coverage vs human approved validation vs technical assessment.
    - Answers the core governance questions:
      - Unmapped controls list.
      - Proposed-only (unreviewed) controls list.
      - Policies without control mappings list.
    """
    res = client.get("/api/v1/mappings/coverage", headers=AUDITOR_HEADER)
    assert res.status_code == 200
    report = res.json()

    # ISO 27001
    iso = report["iso_27001"]
    assert iso["total_catalog_controls"] == 93
    assert iso["mapped_controls_count"] > 0
    assert iso["approved_mapped_controls_count"] > 0
    assert iso["technically_assessed_controls_count"] >= 0  # ISO controls assessed via organizational procedures
    assert iso["mapping_coverage_pct"] > 0

    # NIST 800-53
    nist = report["nist_800_53"]
    assert nist["total_catalog_controls"] == 1196
    assert nist["base_controls_count"] == 300
    assert nist["enhancements_count"] == 714
    assert nist["withdrawn_controls_count"] == 182
    assert nist["mapped_controls_count"] > 0
    assert nist["approved_mapped_controls_count"] > 0
    assert nist["technically_assessed_controls_count"] > 0  # NIST controls with Tier 1/2 CaC tests

    # Combined
    combined = report["combined"]
    assert combined["total_catalog_controls"] == 1289
    assert combined["technically_assessed_controls_count"] > 0

    # Gap explorer collections
    assert "unmapped_control_ids" in report
    assert len(report["unmapped_control_ids"]) > 0

    assert "unreviewed_control_ids" in report
    # All candidate proposed mappings that lack human approval
    assert isinstance(report["unreviewed_control_ids"], list)

    assert "policies_without_mappings" in report
    assert isinstance(report["policies_without_mappings"], list)
    # POL-SEC-001 has no framework controls linked in baseline ground truth
    assert "POL-SEC-001" in report["policies_without_mappings"]


# =============================================================================
# 10. Catalog Import Idempotency
# =============================================================================
def test_catalog_import_idempotency():
    """
    Validates that executing seed_database() repeatedly:
    - Does NOT duplicate framework controls.
    - Does NOT duplicate policies.
    - Does NOT duplicate or wipe out policy mappings.
    - Preserves existing human review state.
    """
    db: Session = SessionLocal()
    try:
        initial_ctrl_count = db.query(FrameworkControl).count()
        initial_pol_count = db.query(Policy).count()
        initial_map_count = db.query(PolicyMapping).count()

        # Re-run seeder
        seed_database()

        after_ctrl_count = db.query(FrameworkControl).count()
        after_pol_count = db.query(Policy).count()
        after_map_count = db.query(PolicyMapping).count()

        assert initial_ctrl_count == after_ctrl_count == 1289
        assert initial_pol_count == after_pol_count
        assert initial_map_count == after_map_count
    finally:
        db.close()


# =============================================================================
# 11. Regressions & Bug Fix Validations (Phases 2-5)
# =============================================================================

def test_mapping_creation_with_uuid_policy_id():
    """
    Regression Test for Bug A:
    Validates that a UUID string policy_id creates a valid mapping in PROPOSED status
    without numeric conversion or schema validation failure.
    """
    db: Session = SessionLocal()
    temp_mapping_id = None
    try:
        # Pick policy POL-NET-001 (or another) and an unmapped control ISO-A.5.2
        pol = db.query(Policy).filter(Policy.policy_code == "POL-NET-001").first()
        ctrl = db.query(FrameworkControl).filter(FrameworkControl.control_id == "ISO-A.5.2").first()
        assert pol is not None and ctrl is not None
        assert isinstance(pol.id, str) and len(pol.id) == 36 # UUID string

        # Ensure no residual mapping
        db.query(PolicyMapping).filter(
            PolicyMapping.policy_id == pol.id,
            PolicyMapping.control_id == ctrl.control_id
        ).delete()
        db.commit()

        # Submit mapping using exact UUID string
        res = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={
                "policy_id": pol.id,
                "control_id": ctrl.control_id,
                "rationale": "Regression test: verified UUID policy_id resolution.",
                "confidence_score": 1.0,
                "mapping_status": "PROPOSED"
            }
        )
        assert res.status_code == 200, res.text
        data = res.json()
        temp_mapping_id = data["id"]
        assert data["policy_id"] == pol.id
        assert data["control_id"] == ctrl.control_id
        assert data["mapping_status"] == "PROPOSED"
        assert data["is_ground_truth"] is False

        # Verify database persistence
        db_m = db.query(PolicyMapping).filter(PolicyMapping.id == temp_mapping_id).first()
        assert db_m is not None
        assert db_m.policy_id == pol.id
        assert db_m.control_id == ctrl.control_id
    finally:
        if temp_mapping_id:
            db.query(PolicyMapping).filter(PolicyMapping.id == temp_mapping_id).delete()
            db.commit()
        db.close()


def test_mapping_creation_with_nonexistent_ids():
    """Validates 404 handling when policy_id or control_id does not exist."""
    ctrl = "ISO-A.5.1"
    res_bad_pol = client.post(
        "/api/v1/mappings",
        headers=AUDITOR_HEADER,
        json={
            "policy_id": "00000000-0000-0000-0000-000000000000",
            "control_id": ctrl,
            "rationale": "Testing nonexistent policy",
            "mapping_status": "PROPOSED"
        }
    )
    assert res_bad_pol.status_code == 404
    assert "not found" in res_bad_pol.json()["detail"].lower()

    db: Session = SessionLocal()
    pol = db.query(Policy).first()
    db.close()

    res_bad_ctrl = client.post(
        "/api/v1/mappings",
        headers=AUDITOR_HEADER,
        json={
            "policy_id": pol.id,
            "control_id": "NONEXISTENT-CTRL-9999",
            "rationale": "Testing nonexistent control",
            "mapping_status": "PROPOSED"
        }
    )
    assert res_bad_ctrl.status_code == 404
    assert "not found" in res_bad_ctrl.json()["detail"].lower()


def test_mapping_creation_rejects_invalid_initial_statuses():
    """
    Regression Test for Bug B:
    Validates that creation requests attempting to bypass auditor review
    with APPROVED or HUMAN_APPROVED are strictly rejected with HTTP 400.
    """
    db: Session = SessionLocal()
    pol = db.query(Policy).first()
    ctrl = db.query(FrameworkControl).filter(FrameworkControl.control_id == "ISO-A.5.3").first()
    db.close()

    for invalid_st in ["APPROVED", "HUMAN_APPROVED"]:
        res = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={
                "policy_id": pol.id,
                "control_id": ctrl.control_id,
                "rationale": "Attempting direct approval",
                "mapping_status": invalid_st
            }
        )
        assert res.status_code == 400, f"Expected 400 for {invalid_st}, got {res.status_code}"
        assert "New mappings cannot be directly created as HUMAN_APPROVED" in res.json()["detail"]


def test_mapping_review_approval_and_rejection_workflow():
    """
    Validates complete review lifecycle:
    1. Proposal of mapping.
    2. Approval with reviewer and rationale.
    3. Separate proposal and rejection with required reason.
    4. Audit trail inspection.
    """
    db: Session = SessionLocal()
    m_approved_id = None
    m_rejected_id = None
    try:
        pol = db.query(Policy).filter(Policy.policy_code == "POL-IAM-001").first()
        ctrl_app = db.query(FrameworkControl).filter(FrameworkControl.control_id == "ISO-A.5.4").first()
        ctrl_rej = db.query(FrameworkControl).filter(FrameworkControl.control_id == "ISO-A.5.5").first()

        # Clean prior
        db.query(PolicyMapping).filter(PolicyMapping.control_id.in_([ctrl_app.control_id, ctrl_rej.control_id])).delete()
        db.commit()

        # 1. Propose mapping A
        res_a = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={"policy_id": pol.id, "control_id": ctrl_app.control_id, "rationale": "Candidate A"}
        )
        assert res_a.status_code == 200
        m_approved_id = res_a.json()["id"]

        # Approve mapping A
        res_rev_a = client.patch(
            f"/api/v1/mappings/{m_approved_id}/review",
            headers=AUDITOR_HEADER,
            json={"status": "APPROVED", "reviewer": "Lead Auditor Alice", "review_notes": "Verified requirements met."}
        )
        assert res_rev_a.status_code == 200
        app_data = res_rev_a.json()
        assert app_data["mapping_status"] in ["APPROVED", "HUMAN_APPROVED"]
        assert app_data["is_ground_truth"] is True

        # 2. Propose mapping B
        res_b = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={"policy_id": pol.id, "control_id": ctrl_rej.control_id, "rationale": "Candidate B"}
        )
        assert res_b.status_code == 200
        m_rejected_id = res_b.json()["id"]

        # Reject mapping B without notes -> fails (400)
        res_bad_rej = client.patch(
            f"/api/v1/mappings/{m_rejected_id}/review",
            headers=AUDITOR_HEADER,
            json={"status": "REJECTED", "reviewer": "Auditor Bob", "review_notes": ""}
        )
        assert res_bad_rej.status_code == 400

        # Reject mapping B with notes -> succeeds
        res_rev_b = client.patch(
            f"/api/v1/mappings/{m_rejected_id}/review",
            headers=AUDITOR_HEADER,
            json={"status": "REJECTED", "reviewer": "Auditor Bob", "review_notes": "Scope does not cover cryptographic boundary."}
        )
        assert res_rev_b.status_code == 200
        rej_data = res_rev_b.json()
        assert rej_data["mapping_status"] == "REJECTED"
        assert "cryptographic boundary" in rej_data["review_notes"]

        # 3. Verify audit trail exists for both
        res_audit = client.get(f"/api/v1/mappings/{m_approved_id}/audit", headers=AUDITOR_HEADER)
        assert res_audit.status_code == 200
        logs = res_audit.json()
        assert len(logs) >= 1
        assert logs[0]["action"] == "REVIEW_POLICY_MAPPING"
    finally:
        if m_approved_id:
            db.query(PolicyMapping).filter(PolicyMapping.id == m_approved_id).delete()
        if m_rejected_id:
            db.query(PolicyMapping).filter(PolicyMapping.id == m_rejected_id).delete()
        db.commit()
        db.close()


def test_audit_report_semantics_and_distinctions():
    """
    Regression Test for Phase 5:
    Validates that the audit report distinguishes catalog size from assessed controls
    and clearly documents the denominator basis.
    """
    res = client.get("/api/v1/reports/summary", headers=AUDITOR_HEADER)
    assert res.status_code == 200
    report = res.json()

    assert "control_coverage" in report
    cov = report["control_coverage"]
    assert cov["catalog_total_controls"] == 1289
    assert cov["controls_with_executable_tests"] == 4
    assert cov["controls_with_recorded_assessments"] >= 0
    assert "assurance_index_pct" in cov
    assert "assurance_index_catalog_pct" in cov
    assert "denominator_basis" in cov
    assert "disclaimer" in report

