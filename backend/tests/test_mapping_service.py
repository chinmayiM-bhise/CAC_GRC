import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import SessionLocal
from app.config import settings
from app.models.policy import Policy
from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.audit_log import AuditLog
from app.services.mapping_service import (
    MappingService,
    extract_concepts,
    tokenize_filtered,
    compute_hybrid_similarity
)
from app.auth import ROLE_AUDITOR, ROLE_ENGINEER, ROLE_ADMIN

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


def test_concept_extraction_across_domains():
    """Validates domain concept extraction across IAM, AUD, DAT, and DEV."""
    # IAM Lockout
    iam_text = "Automatic account lockout after 5 consecutive failed authentication attempts"
    c_iam = extract_concepts(iam_text)
    assert "CONCEPT_ACCOUNT_LOCKOUT" in c_iam

    # IAM Least Privilege
    priv_text = "Direct root or superuser logins prohibited. Audited sudo privilege elevation."
    c_priv = extract_concepts(priv_text)
    assert "CONCEPT_LEAST_PRIVILEGE" in c_priv

    # AUD Logging
    aud_text = "Tamper-evident audit logging subsystem records auditable events"
    c_aud = extract_concepts(aud_text)
    assert "CONCEPT_AUDIT_LOGGING" in c_aud

    # DAT Cryptography
    dat_text = "Database connections cryptographically protected using TLS 1.3 transmission confidentiality"
    c_dat = extract_concepts(dat_text)
    assert "CONCEPT_CRYPTOGRAPHY_TRANSIT" in c_dat

    # DEV Change Management
    dev_text = "Branch protection requires pull request and peer review before merging"
    c_dev = extract_concepts(dev_text)
    assert "CONCEPT_CHANGE_MANAGEMENT" in c_dev


def test_suggest_mappings_preserves_human_review():
    """
    Validates that algorithmic suggestions:
    1. Are marked with status 'SUGGESTED' (never 'HUMAN_APPROVED').
    2. Have is_ground_truth=False.
    3. Have requires_human_review=True.
    4. Provide clear explanatory rationales.
    """
    db = SessionLocal()
    try:
        suggestions = MappingService.suggest_mappings(db, policy_code="POL-IAM-001", threshold=0.20)
        assert len(suggestions) > 0

        for s in suggestions:
            assert s["policy_code"] == "POL-IAM-001"
            assert s["mapping_status"] == "SUGGESTED"
            assert s["is_ground_truth"] is False
            assert s["requires_human_review"] is True
            assert s["confidence_score"] >= 0.20
            assert "Requires independent human auditor review" in s["rationale"]
    finally:
        db.close()


def test_suggest_mappings_api_endpoint_rbac():
    """Tests the GET /api/v1/mappings/suggest endpoint under various roles and without auth."""
    # 1. Unauthenticated request must fail
    res_unauth = client.get("/api/v1/mappings/suggest")
    assert res_unauth.status_code == 401

    # 2. Auditor can query suggestions
    res_auditor = client.get("/api/v1/mappings/suggest?policy_code=POL-IAM-001", headers=AUDITOR_HEADER)
    assert res_auditor.status_code == 200
    data = res_auditor.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert all(item["mapping_status"] == "SUGGESTED" for item in data)
    assert all(item["is_ground_truth"] is False for item in data)


def test_create_mapping_endpoint_restrictions():
    """
    Validates that:
    1. Direct creation as HUMAN_APPROVED is strictly rejected (400).
    2. Creation as SUGGESTED or DRAFT succeeds (200).
    3. Non-auditor / unauthenticated requests fail (401).
    """
    db = SessionLocal()
    temp_mapping = None
    try:
        policy = db.query(Policy).first()
        control = db.query(FrameworkControl).filter(FrameworkControl.control_id == "NIST-IA-5").first()
        # Clean any pre-existing mapping for idempotency
        db.query(PolicyMapping).filter(
            PolicyMapping.policy_id == policy.id,
            PolicyMapping.control_id == control.control_id
        ).delete()
        db.commit()

        # 1. Reject silent direct creation as HUMAN_APPROVED
        res_reject = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={
                "policy_id": policy.id,
                "control_id": control.control_id,
                "mapping_status": "HUMAN_APPROVED",
                "confidence_score": 0.85,
                "rationale": "Attempted direct approval"
            }
        )
        assert res_reject.status_code == 400
        assert "New mappings cannot be directly created as HUMAN_APPROVED" in res_reject.json()["detail"]

        # 2. Create as SUGGESTED succeeds
        res_create = client.post(
            "/api/v1/mappings",
            headers=AUDITOR_HEADER,
            json={
                "policy_id": policy.id,
                "control_id": control.control_id,
                "mapping_status": "SUGGESTED",
                "confidence_score": 0.75,
                "rationale": "Candidate mapping for testing"
            }
        )
        assert res_create.status_code == 200
        created = res_create.json()
        assert created["mapping_status"] == "SUGGESTED"
        assert created["is_ground_truth"] is False
        mapping_id = created["id"]

        temp_mapping = db.query(PolicyMapping).filter(PolicyMapping.id == mapping_id).first()
    finally:
        if temp_mapping:
            db.delete(temp_mapping)
            db.commit()
        db.close()


def test_human_review_workflow_and_role_gating():
    """
    Validates the human-in-the-loop review workflow:
    1. Non-auditor roles cannot certify a mapping as HUMAN_APPROVED.
    2. An authorized auditor or admin can approve or reject a mapping.
    3. Review notes are mandatory when approving or rejecting.
    4. The review action creates an immutable AuditLog entry.
    """
    db = SessionLocal()
    temp_mapping = None
    audit_log = None
    try:
        # Create a temporary draft mapping for testing
        test_policy = db.query(Policy).first()
        test_control = db.query(FrameworkControl).first()

        temp_mapping = PolicyMapping(
            policy_id=test_policy.id,
            control_id=test_control.control_id,
            mapping_status="SUGGESTED",
            is_ground_truth=False,
            confidence_score=0.85,
            rationale="Algorithmic candidate pending review"
        )
        db.add(temp_mapping)
        db.commit()
        db.refresh(temp_mapping)
        mapping_id = temp_mapping.id

        # 1. Review notes are required
        with pytest.raises(ValueError) as excinfo:
            MappingService.review_mapping(
                db=db,
                mapping_id=mapping_id,
                new_status="HUMAN_APPROVED",
                actor="auditor_bob",
                reviewer_role=ROLE_AUDITOR,
                rationale=""
            )
        assert "Review notes (rationale) are required" in str(excinfo.value)

        # 2. Engineer cannot approve mapping (Must raise PermissionError)
        with pytest.raises(PermissionError):
            MappingService.review_mapping(
                db=db,
                mapping_id=mapping_id,
                new_status="HUMAN_APPROVED",
                actor="engineer_alice",
                reviewer_role=ROLE_ENGINEER,
                rationale="Attempted auto-approval by engineer"
            )

        # 3. Auditor CAN approve mapping with valid rationale
        updated = MappingService.review_mapping(
            db=db,
            mapping_id=mapping_id,
            new_status="HUMAN_APPROVED",
            actor="auditor_bob",
            reviewer_role=ROLE_AUDITOR,
            rationale="Reviewed and verified alignment with enterprise security policy."
        )
        assert updated.mapping_status == "HUMAN_APPROVED"
        assert "Reviewed and verified" in updated.rationale

        # 4. Check AuditLog entry
        audit_log = db.query(AuditLog).filter(
            AuditLog.action == "REVIEW_POLICY_MAPPING",
            AuditLog.target == f"mapping:{mapping_id}"
        ).first()
        assert audit_log is not None
        assert audit_log.actor == "auditor_bob"
        assert audit_log.details["new_status"] == "HUMAN_APPROVED"
        assert audit_log.details["reviewer_role"] == ROLE_AUDITOR
    finally:
        # Guarantee full cleanup
        if temp_mapping:
            db.delete(temp_mapping)
        if audit_log:
            db.delete(audit_log)
        db.commit()
        db.close()


def test_review_mapping_api_endpoint():
    """Tests the PATCH /api/v1/mappings/{mapping_id}/review endpoint."""
    db = SessionLocal()
    temp_mapping = None
    mapping_id = None
    try:
        test_policy = db.query(Policy).first()
        test_control = db.query(FrameworkControl).first()

        temp_mapping = PolicyMapping(
            policy_id=test_policy.id,
            control_id=test_control.control_id,
            mapping_status="SUGGESTED",
            is_ground_truth=False,
            confidence_score=0.75,
            rationale="Test candidate"
        )
        db.add(temp_mapping)
        db.commit()
        db.refresh(temp_mapping)
        mapping_id = temp_mapping.id

        # 1. Unauthenticated request fails with 401
        res_no_auth = client.patch(
            f"/api/v1/mappings/{mapping_id}/review",
            json={"status": "HUMAN_APPROVED", "rationale": "Approve"}
        )
        assert res_no_auth.status_code == 401

        # 2. Missing rationale fails with 400
        res_no_notes = client.patch(
            f"/api/v1/mappings/{mapping_id}/review",
            headers=AUDITOR_HEADER,
            json={"status": "HUMAN_APPROVED", "rationale": ""}
        )
        assert res_no_notes.status_code == 400
        assert "Review notes (rationale) are required" in res_no_notes.json()["detail"]

        # 3. Invalid mapping ID fails with 404
        res_invalid_id = client.patch(
            "/api/v1/mappings/invalid-uuid-99999/review",
            headers=AUDITOR_HEADER,
            json={"status": "HUMAN_APPROVED", "rationale": "Valid notes"}
        )
        assert res_invalid_id.status_code == 404
        assert "not found" in res_invalid_id.json()["detail"]

        # 4. Auditor approves mapping successfully (200)
        res_auditor = client.patch(
            f"/api/v1/mappings/{mapping_id}/review",
            headers=AUDITOR_HEADER,
            json={"status": "HUMAN_APPROVED", "rationale": "Auditor verified mapping validity."}
        )
        assert res_auditor.status_code == 200
        data = res_auditor.json()
        assert data["mapping_status"] == "HUMAN_APPROVED"

        # 5. Auditor rejects mapping with reason (200)
        res_reject = client.patch(
            f"/api/v1/mappings/{mapping_id}/review",
            headers=AUDITOR_HEADER,
            json={"status": "REJECTED", "rationale": "Control scope does not cover stated requirements."}
        )
        assert res_reject.status_code == 200
        assert res_reject.json()["mapping_status"] == "REJECTED"

    finally:
        # Guarantee full cleanup
        if mapping_id:
            audit_logs = db.query(AuditLog).filter(AuditLog.target == f"mapping:{mapping_id}").all()
            for al in audit_logs:
                db.delete(al)
        if temp_mapping:
            db.delete(temp_mapping)
        db.commit()
        db.close()


def test_mapping_audit_trail_endpoints():
    """Validates mapping audit log retrieval endpoints."""
    db = SessionLocal()
    temp_mapping = None
    mapping_id = None
    try:
        test_policy = db.query(Policy).first()
        test_control = db.query(FrameworkControl).first()

        temp_mapping = PolicyMapping(
            policy_id=test_policy.id,
            control_id=test_control.control_id,
            mapping_status="SUGGESTED",
            is_ground_truth=False,
            confidence_score=0.75,
            rationale="Test candidate"
        )
        db.add(temp_mapping)
        db.commit()
        db.refresh(temp_mapping)
        mapping_id = temp_mapping.id

        # Perform a review action to create an audit record
        res_review = client.patch(
            f"/api/v1/mappings/{mapping_id}/review",
            headers=AUDITOR_HEADER,
            json={"status": "HUMAN_APPROVED", "rationale": "Auditor test review justification."}
        )
        assert res_review.status_code == 200

        # Query mapping audit trail
        res_audit = client.get(f"/api/v1/mappings/{mapping_id}/audit", headers=AUDITOR_HEADER)
        assert res_audit.status_code == 200
        logs = res_audit.json()
        assert len(logs) >= 1
        latest_log = logs[0]
        assert latest_log["action"] == "REVIEW_POLICY_MAPPING"
        assert latest_log["target"] == f"mapping:{mapping_id}"
        assert latest_log["details"]["new_status"] == "HUMAN_APPROVED"
        assert "Auditor test review justification." in latest_log["details"]["rationale"]

        # Non-existent mapping audit returns 404
        res_404 = client.get("/api/v1/mappings/non-existent-id/audit", headers=AUDITOR_HEADER)
        assert res_404.status_code == 404

        # Query platform-wide mapping audit log
        res_all_audit = client.get("/api/v1/audit/mappings?limit=10", headers=AUDITOR_HEADER)
        assert res_all_audit.status_code == 200
        all_logs = res_all_audit.json()
        assert isinstance(all_logs, list)
        assert any(l["target"] == f"mapping:{mapping_id}" for l in all_logs)

    finally:
        if mapping_id:
            audit_logs = db.query(AuditLog).filter(AuditLog.target == f"mapping:{mapping_id}").all()
            for al in audit_logs:
                db.delete(al)
        if temp_mapping:
            db.delete(temp_mapping)
        db.commit()
        db.close()


def test_frontend_dashboard_mapping_integration():
    """
    Validates that the Single-Page Dashboard (/dashboard):
    1. Returns 200 and loads index.html.
    2. Contains the Policy Mapping navigation item and breadcrumbs.
    3. Contains sub-tabs for Active Baseline, Hybrid Suggestions, and Audit Trail.
    4. Distinguishes SUGGESTED from HUMAN_APPROVED visually.
    5. Contains the human review modal, mandatory review notes input, and audit trail views.
    6. Contains the regulatory caution notice.
    """
    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.text

    # Navigation item
    assert 'id="nav-mappings"' in html
    assert 'Policy Mappings' in html

    # Tab titles and views
    assert 'Active Compliance Baseline' in html
    assert 'Hybrid Semantic AI Suggestions' in html
    assert 'Mapping Review Audit Trail' in html

    # Tooling bar controls
    assert 'id="select-suggest-policy"' in html
    assert 'id="input-suggest-threshold"' in html
    assert 'id="btn-fetch-suggestions"' in html

    # Regulatory Notice
    assert 'Regulatory Assurance Notice:' in html
    assert 'certifies regulatory compliance' in html
    assert 'NEVER' in html

    # Review Modal & notes input
    assert 'id="mapping-review-modal"' in html
    assert 'id="review-notes-input"' in html
    assert 'id="btn-submit-review"' in html
    assert 'HUMAN_APPROVED' in html
    assert 'REJECTED' in html

    # Audit modal
    assert 'id="mapping-audit-modal"' in html
    assert 'id="mapping-audit-content"' in html

    # Status distinguishing
    assert 'SUGGESTED (UNVERIFIED)' in html
