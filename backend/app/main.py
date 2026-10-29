from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any, Union
from pathlib import Path
import datetime
import socket
from urllib.parse import urlparse

from app.config import settings
from app.database import get_db, Base, engine
from app.migrate import run_migrations
from app.auth import require_role, get_current_role, ROLE_AUDITOR, ROLE_ENGINEER, ROLE_ADMIN

from app.models.policy import Policy
from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.test_definition import TestDefinition
from app.models.evidence import EvidenceRecord
from app.models.score import EWCESScore
from app.models.finding import Finding
from app.models.assessment import AssessmentRun
from app.models.audit_log import AuditLog
from app.models.chaos import ChaosDriftRecord
from app.models.base import utc_now

from app.schemas.policy import (
    PolicyResponse,
    PolicyCreate,
    PolicyUpdate,
    PolicyReviewRequest
)
from app.schemas.framework import FrameworkControlResponse
from app.schemas.mapping import (
    PolicyMappingResponse,
    PolicyMappingCreate,
    MappingSuggestionResponse,
    MappingReviewRequest,
    MappingAuditLogResponse,
    MappingCoverageReport
)
from app.schemas.test_definition import TestDefinitionResponse
from app.schemas.evidence import EvidenceRecordResponse, CheckpointArtifactSchema, CheckpointVerificationResponse
from app.schemas.score import EWCESScoreResponse
from app.schemas.finding import (
    FindingResponse,
    FindingCreate,
    FindingUpdate,
    FindingRiskWaiverRequest
)
from app.schemas.assessment import (
    AssessmentRunResponse,
    AssessmentTaskAcceptedResponse,
    AssessmentTaskStatusResponse
)

from app.engine.orchestrator import TestOrchestrator
from app.engine.ledger.vault import EvidenceVault
from app.engine.scoring.classifier import EWCESClassifier
from app.chaos.mutations import ChaosInjector, DRIFT_CATALOG

from app.services.assurance_service import AssuranceService
from app.services.finding_service import FindingService
from app.services.ledger_service import LedgerService
from app.services.asset_service import AssetService
from app.services.mapping_service import MappingService

# Run incremental schema migrations on boot
run_migrations()

orchestrator = TestOrchestrator()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Continuous Automated Compliance (CAC) & Evidence-Weighted Scoring (EW-CES) Platform",
    version="2.1.0"
)

# Enable CORS with restricted origin list (eliminating wildcard credentials vulnerability)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

static_dir = Path(__file__).resolve().parent / "static"


@app.on_event("startup")
def bootstrap_database_if_empty():
    """Guarantees the database is never empty or uninitialized on platform boot."""
    from app.database import SessionLocal
    from app.models.framework import FrameworkControl
    from app.seed_data.seed import seed_database
    db = SessionLocal()
    try:
        control_count = db.query(FrameworkControl).count()
        if control_count == 0:
            print("[*] Fresh database detected with 0 controls. Auto-bootstrapping authoritative ISO 27001 & NIST 800-53 catalog...")
            seed_database()
            print("[+] Auto-bootstrap successful.")
    except Exception as exc:
        print(f"[!] Database startup verification warning: {exc}")
    finally:
        db.close()


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    """Serves the single-page application dashboard."""
    return FileResponse(static_dir / "index.html")


@app.get("/api/v1/health", tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    """Public unauthenticated health and heartbeat probe with component diagnostics."""
    controls_count = 0
    policies_count = 0
    try:
        controls_count = db.query(FrameworkControl).count()
        policies_count = db.query(Policy).count()
    except Exception:
        pass

    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "database": settings.DATABASE_URL.split("///")[0],
        "database_file": settings.DATABASE_URL.split("///")[-1] if "sqlite" in settings.DATABASE_URL else "postgresql",
        "version": "2.1.0",
        "environment": settings.ENVIRONMENT,
        "auth_enabled": settings.AUTH_ENABLED,
        "dev_auth_bypass": settings.DEV_AUTH_BYPASS,
        "controls_loaded": controls_count,
        "policies_loaded": policies_count,
        "utc_time": utc_now().isoformat()
    }


@app.get("/api/v1/auth/me", tags=["Authentication"])
def get_current_auth_session(role: str = Depends(get_current_role)):
    """
    Validates bearer token / X-API-Key and returns the authenticated role.
    Used by dashboard and automation clients to verify credentials and check role capabilities.
    """
    return {
        "authenticated": True,
        "role": role,
        "role_display": role.capitalize(),
        "auth_enabled": settings.AUTH_ENABLED,
        "utc_time": utc_now().isoformat()
    }


@app.get("/api/v1/overview", tags=["Overview"])
def get_platform_overview(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Authoritative platform-wide metrics consumed by dashboard overview and executive reports."""
    return AssuranceService.get_assurance_overview(db)


# ----------------- POLICIES -----------------
@app.get("/api/v1/policies", response_model=List[PolicyResponse], tags=["Policies"])
def list_policies(
    category: Optional[str] = Query(None, description="Filter by category"),
    status: Optional[str] = Query(None, description="Filter by lifecycle status (DRAFT, UNDER_REVIEW, APPROVED, REJECTED, ARCHIVED, DEPRECATED)"),
    q: Optional[str] = Query(None, description="Search by code, title, description, or category"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    query = db.query(Policy)
    if category and category.upper() != "ALL":
        query = query.filter(Policy.category == category)
    if status and status.upper() != "ALL":
        norm_status = status.upper()
        if norm_status in ["ARCHIVED", "DEPRECATED"]:
            query = query.filter(Policy.lifecycle_status.in_(["ARCHIVED", "DEPRECATED"]))
        elif norm_status in ["IN_REVIEW", "UNDER_REVIEW"]:
            query = query.filter(Policy.lifecycle_status.in_(["IN_REVIEW", "UNDER_REVIEW"]))
        else:
            query = query.filter(Policy.lifecycle_status == norm_status)
    if q:
        from sqlalchemy import or_, func
        q_term = f"%{q.lower()}%"
        query = query.filter(
            or_(
                func.lower(Policy.policy_code).like(q_term),
                func.lower(Policy.title).like(q_term),
                func.lower(Policy.description).like(q_term),
                func.lower(Policy.category).like(q_term)
            )
        )
    return query.all()


@app.get("/api/v1/policies/{policy_code}", response_model=PolicyResponse, tags=["Policies"])
def get_policy(
    policy_code: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    policy = db.query(Policy).filter(Policy.policy_code == policy_code).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy {policy_code} not found")
    return policy


@app.get("/api/v1/policies/{policy_code}/controls", tags=["Policies"])
def get_policy_controls(
    policy_code: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Returns all framework controls mapped to a specific policy."""
    policy = db.query(Policy).filter(Policy.policy_code == policy_code).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_code}' not found.")
    
    results = []
    for m in policy.mappings:
        c = m.framework_control
        results.append({
            "mapping_id": m.id,
            "control_id": m.control_id,
            "control_code": c.control_code if c else None,
            "control_title": c.title if c else None,
            "framework_name": c.framework_name if c else None,
            "framework_version": getattr(c, "framework_version", "2022") if c else None,
            "domain_family": c.domain_family if c else None,
            "mapping_status": m.mapping_status,
            "is_ground_truth": m.is_ground_truth,
            "confidence_score": m.confidence_score,
            "rationale": m.rationale,
            "reviewer": m.reviewer,
            "reviewed_at": m.reviewed_at.isoformat() if m.reviewed_at else None
        })
    return results


@app.post("/api/v1/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED, tags=["Policies"])
def create_policy(
    policy_data: PolicyCreate,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ENGINEER))
):
    """Creates a new organizational policy in DRAFT status."""
    existing = db.query(Policy).filter(Policy.policy_code == policy_data.policy_code).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Policy with code '{policy_data.policy_code}' already exists.")

    new_policy = Policy(
        policy_code=policy_data.policy_code,
        title=policy_data.title,
        description=policy_data.description,
        category=policy_data.category,
        version=policy_data.version,
        owner=policy_data.owner or "CISO Office",
        purpose=policy_data.purpose,
        statement=policy_data.statement,
        scope=policy_data.scope or "Enterprise Infrastructure & Systems",
        required_evidence_desc=policy_data.required_evidence_desc,
        lifecycle_status="DRAFT",
        is_sample=False
    )
    db.add(new_policy)
    db.commit()
    db.refresh(new_policy)
    return new_policy


@app.put("/api/v1/policies/{policy_code}", response_model=PolicyResponse, tags=["Policies"])
@app.patch("/api/v1/policies/{policy_code}", response_model=PolicyResponse, tags=["Policies"])
def update_policy(
    policy_code: str,
    policy_data: PolicyUpdate,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ENGINEER))
):
    """Updates an existing organizational policy."""
    policy = db.query(Policy).filter(Policy.policy_code == policy_code).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_code}' not found.")

    if policy_data.title is not None:
        policy.title = policy_data.title
    if policy_data.description is not None:
        policy.description = policy_data.description
    if policy_data.category is not None:
        policy.category = policy_data.category
    if policy_data.version is not None:
        policy.version = policy_data.version
    if policy_data.owner is not None:
        policy.owner = policy_data.owner
    if policy_data.purpose is not None:
        policy.purpose = policy_data.purpose
    if policy_data.statement is not None:
        policy.statement = policy_data.statement
    if policy_data.scope is not None:
        policy.scope = policy_data.scope
    if policy_data.required_evidence_desc is not None:
        policy.required_evidence_desc = policy_data.required_evidence_desc
    if policy_data.approver is not None:
        policy.approver = policy_data.approver
    if policy_data.effective_date is not None:
        policy.effective_date = policy_data.effective_date
    if policy_data.review_date is not None:
        policy.review_date = policy_data.review_date

    policy.updated_at = utc_now()
    db.commit()
    db.refresh(policy)
    return policy


@app.patch("/api/v1/policies/{policy_code}/submit", response_model=PolicyResponse, tags=["Policies"])
def submit_policy_for_review(
    policy_code: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(ROLE_ENGINEER))
):
    """Submits a DRAFT policy for executive/auditor review."""
    policy = db.query(Policy).filter(Policy.policy_code == policy_code).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_code}' not found.")
    if policy.lifecycle_status not in ("DRAFT", "REJECTED"):
        raise HTTPException(status_code=400, detail=f"Policy in status '{policy.lifecycle_status}' cannot be submitted.")

    policy.lifecycle_status = "UNDER_REVIEW"
    policy.updated_at = utc_now()
    
    audit = AuditLog(
        actor=f"role:{role}",
        action="SUBMIT_POLICY_FOR_REVIEW",
        target=f"policy:{policy_code}",
        outcome="SUCCESS",
        details={"status": "UNDER_REVIEW"}
    )
    db.add(audit)
    db.commit()
    db.refresh(policy)
    return policy


@app.patch("/api/v1/policies/{policy_code}/review", response_model=PolicyResponse, tags=["Policies"])
def review_policy(
    policy_code: str,
    review_data: PolicyReviewRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(ROLE_AUDITOR))
):
    """Approves or Rejects a policy under review. Requires Auditor or Admin role."""
    policy = db.query(Policy).filter(Policy.policy_code == policy_code).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_code}' not found.")

    if review_data.action.upper() == "APPROVE":
        policy.lifecycle_status = "APPROVED"
        policy.approver = review_data.approver
        policy.effective_date = review_data.effective_date or utc_now()
        policy.review_date = review_data.review_date or (utc_now() + datetime.timedelta(days=365))
        policy.rejection_reason = None
    elif review_data.action.upper() == "REJECT":
        if not review_data.rejection_reason or len(review_data.rejection_reason.strip()) < 5:
            raise HTTPException(status_code=400, detail="Rejection requires an explicit reason (minimum 5 characters).")
        policy.lifecycle_status = "REJECTED"
        policy.rejection_reason = review_data.rejection_reason
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use 'APPROVE' or 'REJECT'.")

    policy.updated_at = utc_now()
    audit = AuditLog(
        actor=f"role:{role}",
        action=f"REVIEW_POLICY_{review_data.action.upper()}",
        target=f"policy:{policy_code}",
        outcome="SUCCESS",
        details={"status": policy.lifecycle_status, "approver": review_data.approver, "reason": review_data.rejection_reason}
    )
    db.add(audit)
    db.commit()
    db.refresh(policy)
    return policy


@app.patch("/api/v1/policies/{policy_code}/archive", response_model=PolicyResponse, tags=["Policies"])
@app.patch("/api/v1/policies/{policy_code}/deprecate", response_model=PolicyResponse, tags=["Policies"])
def archive_policy(
    policy_code: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(ROLE_ADMIN))
):
    """Marks a policy as ARCHIVED / DEPRECATED. Restricted to Admin role."""
    policy = db.query(Policy).filter(Policy.policy_code == policy_code).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_code}' not found.")
    policy.lifecycle_status = "ARCHIVED"
    policy.updated_at = utc_now()
    audit = AuditLog(
        actor=f"role:{role}",
        action="ARCHIVE_POLICY",
        target=f"policy:{policy_code}",
        outcome="SUCCESS",
        details={"status": "ARCHIVED"}
    )
    db.add(audit)
    db.commit()
    db.refresh(policy)
    return policy


@app.delete("/api/v1/policies/{policy_code}", status_code=status.HTTP_204_NO_CONTENT, tags=["Policies"])
def delete_policy(
    policy_code: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ADMIN))
):
    """Deletes an organizational policy (allowed only for DRAFT or REJECTED policies)."""
    policy = db.query(Policy).filter(Policy.policy_code == policy_code).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{policy_code}' not found.")
    if policy.lifecycle_status not in ("DRAFT", "REJECTED"):
        raise HTTPException(status_code=400, detail=f"Cannot delete policy in '{policy.lifecycle_status}' status. Deprecate it instead.")
    db.delete(policy)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ----------------- FRAMEWORK CONTROLS -----------------
@app.get("/api/v1/controls", response_model=List[FrameworkControlResponse], tags=["Framework Controls"])
def list_controls(
    framework: Optional[str] = Query(None, description="Filter by framework (e.g. NIST_SP_800_53_R5 or ISO_27001_2022)"),
    domain_family: Optional[str] = Query(None, description="Filter by domain family / category"),
    assessment_method: Optional[str] = Query(None, description="Filter by TECHNICAL_AUTOMATED or ORGANIZATIONAL_MANUAL"),
    is_enhancement: Optional[bool] = Query(None, description="Filter base controls vs enhancements"),
    status: Optional[str] = Query(None, description="Filter by ACTIVE or WITHDRAWN"),
    mapped: Optional[bool] = Query(None, description="Filter controls that are mapped vs unmapped"),
    q: Optional[str] = Query(None, description="Search by ID, code, title, description, or requirement"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    query = db.query(FrameworkControl)
    if framework and framework.upper() != "ALL":
        query = query.filter(FrameworkControl.framework_name == framework)
    if domain_family and domain_family.upper() != "ALL":
        query = query.filter(FrameworkControl.domain_family == domain_family)
    if assessment_method and assessment_method.upper() != "ALL":
        query = query.filter(FrameworkControl.assessment_method == assessment_method)
    if is_enhancement is not None:
        query = query.filter(FrameworkControl.is_enhancement == is_enhancement)
    if status and status.upper() != "ALL":
        query = query.filter(FrameworkControl.status == status)
    if mapped is not None:
        mapped_subquery = db.query(PolicyMapping.control_id).distinct()
        if mapped:
            query = query.filter(FrameworkControl.control_id.in_(mapped_subquery))
        else:
            query = query.filter(FrameworkControl.control_id.not_in(mapped_subquery))
    if q:
        from sqlalchemy import or_, func
        q_term = f"%{q.lower()}%"
        query = query.filter(
            or_(
                func.lower(FrameworkControl.control_id).like(q_term),
                func.lower(FrameworkControl.control_code).like(q_term),
                func.lower(FrameworkControl.title).like(q_term),
                func.lower(FrameworkControl.description).like(q_term),
                func.lower(FrameworkControl.domain_family).like(q_term)
            )
        )
    return query.all()


@app.get("/api/v1/controls/{control_id}", tags=["Framework Controls"])
def get_control_detail(
    control_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Returns detailed control metadata including enhancements and linked policies."""
    ctrl = db.query(FrameworkControl).filter(FrameworkControl.control_id == control_id).first()
    if not ctrl:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found.")
    
    enhancements = []
    if not ctrl.is_enhancement:
        enhancements = [
            {"control_id": e.control_id, "control_code": e.control_code, "title": e.title, "status": e.status}
            for e in db.query(FrameworkControl).filter(FrameworkControl.parent_control_id == ctrl.control_id).all()
        ]
    
    linked_policies = []
    for m in ctrl.mappings:
        linked_policies.append({
            "mapping_id": m.id,
            "policy_id": m.policy_id,
            "policy_code": m.policy.policy_code if m.policy else None,
            "policy_title": m.policy.title if m.policy else None,
            "mapping_status": m.mapping_status,
            "confidence_score": m.confidence_score,
            "rationale": m.rationale,
            "reviewer": m.reviewer,
            "reviewed_at": m.reviewed_at.isoformat() if m.reviewed_at else None
        })

    return {
        "control_id": ctrl.control_id,
        "framework_name": ctrl.framework_name,
        "framework_version": getattr(ctrl, "framework_version", "2022"),
        "control_code": ctrl.control_code,
        "title": ctrl.title,
        "description": ctrl.description,
        "domain_family": ctrl.domain_family,
        "assessment_method": ctrl.assessment_method,
        "official_requirement": ctrl.official_requirement,
        "guidance": ctrl.guidance,
        "is_enhancement": ctrl.is_enhancement,
        "parent_control_id": ctrl.parent_control_id,
        "status": ctrl.status,
        "provenance": ctrl.provenance,
        "enhancements": enhancements,
        "linked_policies": linked_policies,
    }


# ----------------- MAPPINGS -----------------
@app.get("/api/v1/mappings/coverage", response_model=MappingCoverageReport, tags=["Policy Mappings"])
def get_mapping_coverage(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """
    Returns comprehensive multi-dimensional compliance mapping coverage report.
    Answers:
    - Total catalog controls vs mapped controls
    - Approved vs unreviewed/proposed mappings
    - Controls with no linked policy (unmapped controls)
    - Controls linked only through unreviewed mappings
    - Policies with no control mappings
    - Controls with technical automated test definitions
    """
    return MappingService.get_coverage_report(db)


@app.get("/api/v1/mappings", response_model=List[PolicyMappingResponse], tags=["Policy Mappings"])
def list_mappings(
    policy_code: Optional[str] = Query(None, description="Filter by policy code"),
    policy_id: Optional[str] = Query(None, description="Filter by policy id"),
    control_id: Optional[str] = Query(None, description="Filter by framework control id"),
    framework: Optional[str] = Query(None, description="Filter by framework name"),
    status: Optional[str] = Query(None, description="Filter by mapping status (PROPOSED, APPROVED, REJECTED, etc.)"),
    is_ground_truth: Optional[bool] = Query(None, description="Filter by ground truth status"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    query = db.query(PolicyMapping)
    if policy_id:
        query = query.filter(PolicyMapping.policy_id == policy_id)
    if policy_code:
        pol = db.query(Policy).filter(Policy.policy_code == policy_code).first()
        if pol:
            query = query.filter(PolicyMapping.policy_id == pol.id)
        else:
            return []
    if control_id:
        query = query.filter(PolicyMapping.control_id == control_id)
    if framework and framework.upper() != "ALL":
        query = query.join(FrameworkControl).filter(FrameworkControl.framework_name == framework)
    if status and status.upper() != "ALL":
        norm_status = status.upper()
        if norm_status == "APPROVED":
            query = query.filter(PolicyMapping.mapping_status.in_(["APPROVED", "HUMAN_APPROVED"]))
        elif norm_status in ["PROPOSED", "SUGGESTED"]:
            query = query.filter(PolicyMapping.mapping_status.in_(["PROPOSED", "SUGGESTED", "DRAFT"]))
        else:
            query = query.filter(PolicyMapping.mapping_status == norm_status)
    if is_ground_truth is not None:
        query = query.filter(PolicyMapping.is_ground_truth == is_ground_truth)
    return query.all()


@app.post("/api/v1/mappings", response_model=PolicyMappingResponse, tags=["Policy Mappings"])
def create_mapping(
    mapping_data: PolicyMappingCreate,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(ROLE_AUDITOR))
):
    """
    Creates a new policy mapping record with status PROPOSED (or SUGGESTED / DRAFT).
    Prevents directly creating mappings as HUMAN_APPROVED or APPROVED without explicit human review.
    Enforces duplicate prevention across (policy_id, control_id).
    """
    norm_status = (mapping_data.mapping_status or "PROPOSED").upper()
    if norm_status in ["HUMAN_APPROVED", "APPROVED"]:
        raise HTTPException(
            status_code=400,
            detail="New mappings cannot be directly created as HUMAN_APPROVED. Initial mappings must start as PROPOSED and proceed through authorized human review."
        )
    if norm_status not in ["PROPOSED", "SUGGESTED", "DRAFT"]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid initial mapping status '{mapping_data.mapping_status}'. Initial mappings must start as PROPOSED."
        )

    # Support resolving policy_code if passed as policy_id
    pol_id = mapping_data.policy_id.strip() if isinstance(mapping_data.policy_id, str) else str(mapping_data.policy_id)
    policy = db.query(Policy).filter(
        (Policy.id == pol_id) | (Policy.policy_code == pol_id)
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{pol_id}' not found.")
    pol_id = policy.id

    # Verify control exists
    control_id_clean = mapping_data.control_id.strip() if isinstance(mapping_data.control_id, str) else str(mapping_data.control_id)
    ctrl = db.query(FrameworkControl).filter(FrameworkControl.control_id == control_id_clean).first()
    if not ctrl:
        raise HTTPException(status_code=404, detail=f"Control '{mapping_data.control_id}' not found.")

    # Check duplicate prevention
    existing = db.query(PolicyMapping).filter(
        PolicyMapping.policy_id == pol_id,
        PolicyMapping.control_id == control_id_clean
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Mapping between policy '{policy.policy_code}' and control '{control_id_clean}' already exists."
        )

    new_mapping = PolicyMapping(
        policy_id=pol_id,
        control_id=control_id_clean,
        mapping_status=norm_status,
        is_ground_truth=False,
        confidence_score=mapping_data.confidence_score or 1.0,
        rationale=mapping_data.rationale
    )
    db.add(new_mapping)

    audit = AuditLog(
        actor=f"role:{role}",
        action="CREATE_POLICY_MAPPING",
        target=f"mapping:{new_mapping.id}",
        outcome="SUCCESS",
        details={
            "policy_code": policy.policy_code,
            "control_id": control_id_clean,
            "mapping_status": new_mapping.mapping_status,
            "rationale": mapping_data.rationale
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(new_mapping)
    return new_mapping


@app.delete("/api/v1/mappings/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Policy Mappings"])
def delete_mapping(
    mapping_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(ROLE_AUDITOR))
):
    """Deletes an existing policy mapping with audit logging."""
    try:
        actor = f"role:{role}"
        MappingService.delete_mapping(db, mapping_id, actor, role)
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


@app.get("/api/v1/mappings/suggest", response_model=List[MappingSuggestionResponse], tags=["Policy Mappings"])
def suggest_policy_mappings(
    policy_code: Optional[str] = Query(None, description="Filter suggestions by policy code"),
    threshold: float = Query(0.20, ge=0.0, le=1.0, description="Minimum hybrid semantic similarity threshold"),
    limit: int = Query(10, ge=1, le=50, description="Max candidate suggestions per policy"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """
    Suggests policy-to-control mappings using the hybrid domain lexicon & TF-IDF similarity matcher.
    Guarantees suggestions default to status SUGGESTED and never silently certify compliance.
    """
    return MappingService.suggest_mappings(db, policy_code=policy_code, threshold=threshold, limit=limit)


@app.patch("/api/v1/mappings/{mapping_id}/review", response_model=PolicyMappingResponse, tags=["Policy Mappings"])
def review_mapping(
    mapping_id: str,
    review_data: MappingReviewRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_role(ROLE_AUDITOR))
):
    """
    Allows an authorized auditor or admin to review and approve/reject a policy mapping.
    Prevents algorithmic self-approval of regulatory equivalence.
    """
    try:
        actor = f"role:{role}"
        effective_rationale = review_data.rationale or review_data.review_notes
        reviewer_name = review_data.reviewer or actor
        return MappingService.review_mapping(
            db=db,
            mapping_id=mapping_id,
            new_status=review_data.status,
            actor=actor,
            reviewer_role=role,
            rationale=effective_rationale,
            reviewer=reviewer_name
        )
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        err_msg = str(ve)
        if "not found" in err_msg.lower():
            raise HTTPException(status_code=404, detail=err_msg)
        raise HTTPException(status_code=400, detail=err_msg)


@app.get("/api/v1/mappings/{mapping_id}/audit", response_model=List[MappingAuditLogResponse], tags=["Policy Mappings"])
def get_mapping_audit_history(
    mapping_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Returns the immutable audit history of review decisions for a given mapping."""
    mapping = db.query(PolicyMapping).filter(PolicyMapping.id == mapping_id).first()
    if not mapping:
        raise HTTPException(status_code=404, detail=f"PolicyMapping with id '{mapping_id}' not found.")

    return db.query(AuditLog).filter(
        AuditLog.action == "REVIEW_POLICY_MAPPING",
        AuditLog.target == f"mapping:{mapping_id}"
    ).order_by(AuditLog.timestamp.desc()).all()


@app.get("/api/v1/audit/mappings", response_model=List[MappingAuditLogResponse], tags=["Policy Mappings"])
def list_all_mapping_audit_logs(
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Returns recent mapping review audit log entries across the platform."""
    return db.query(AuditLog).filter(
        AuditLog.action == "REVIEW_POLICY_MAPPING"
    ).order_by(AuditLog.timestamp.desc()).limit(limit).all()


# ----------------- TEST DEFINITIONS (CaC) -----------------
@app.get("/api/v1/tests", response_model=List[TestDefinitionResponse], tags=["Compliance Tests"])
def list_tests(
    tier: Optional[int] = Query(None, description="Filter by Tier (1=Config, 2=Behavioral)"),
    target_type: Optional[str] = Query(None, description="Filter by target (LINUX_VM, POSTGRES_DB)"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    query = db.query(TestDefinition)
    if tier is not None:
        query = query.filter(TestDefinition.tier == tier)
    if target_type:
        query = query.filter(TestDefinition.target_type == target_type)
    return query.all()


# ----------------- EVIDENCE VAULT -----------------
@app.get("/api/v1/evidence", response_model=List[EvidenceRecordResponse], tags=["Evidence Vault"])
def list_evidence(
    test_id: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    return LedgerService.list_evidence(db, test_id=test_id, limit=limit)


# ----------------- EW-CES SCORES -----------------
@app.get("/api/v1/scores", response_model=List[EWCESScoreResponse], tags=["EW-CES Scoring"])
def list_scores(
    framework: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    return AssuranceService.get_latest_control_scores(db, framework=framework)


@app.post("/api/v1/scores/re-evaluate", response_model=List[EWCESScoreResponse], tags=["EW-CES Scoring"])
def reevaluate_all_scores(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ENGINEER))
):
    """Triggers EW-CES 4-State evaluation across all framework controls. Requires engineer or admin role."""
    return AssuranceService.reevaluate_all(db)


# ----------------- ORCHESTRATION & EXECUTION -----------------
@app.post(
    "/api/v1/orchestrator/run-all",
    response_model=Union[AssessmentTaskAcceptedResponse, Dict[str, Any]],
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Orchestrator"]
)
def run_all_compliance_tests(
    background_tasks: BackgroundTasks,
    response: Response,
    allow_simulation: bool = Query(True, description="Use deterministic simulation if lab targets are offline"),
    sync: bool = Query(False, description="Run synchronously (HTTP 200) instead of background job (HTTP 202)"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ENGINEER))
):
    """
    Executes all Compliance-as-Code tests across monitored targets.
    By default (sync=False), queues execution in the background and returns HTTP 202 with task_id.
    Query GET /api/v1/orchestrator/status/{task_id} to poll progress.
    Requires engineer or admin role.
    """
    if sync:
        response.status_code = status.HTTP_200_OK
        return orchestrator.execute_all_tests(db, allow_simulation=allow_simulation)

    task_payload = orchestrator.create_task(allow_simulation=allow_simulation, run_type="MANUAL_ADHOC")
    background_tasks.add_task(
        orchestrator.run_background_assessment,
        task_id=task_payload["task_id"],
        allow_simulation=allow_simulation,
        run_type="MANUAL_ADHOC"
    )
    response.status_code = status.HTTP_202_ACCEPTED
    return task_payload


@app.get(
    "/api/v1/orchestrator/status/{task_id}",
    response_model=AssessmentTaskStatusResponse,
    tags=["Orchestrator"]
)
def get_assessment_status(
    task_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """
    Retrieves the execution status and results of an assessment task.
    Supports both active background tasks and historical assessment runs.
    Requires auditor, engineer, or admin role.
    """
    task = orchestrator.get_task_status(db, task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Assessment task '{task_id}' not found.")
    return task


@app.post("/api/v1/orchestrator/run/{test_id}", tags=["Orchestrator"])
def run_single_test(
    test_id: str,
    allow_simulation: bool = Query(True),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ENGINEER))
):
    """Executes a single test, commits evidence to the ledger, and returns execution result. Requires engineer or admin role."""
    try:
        return orchestrator.execute_test(db, test_id, allow_simulation=allow_simulation)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ----------------- FINDINGS & REMEDIATION -----------------
@app.get("/api/v1/findings", response_model=List[FindingResponse], tags=["Findings & Remediation"])
def list_findings(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    control_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    return FindingService.list_findings(db, status=status, severity=severity, control_id=control_id)


@app.patch("/api/v1/findings/{finding_id}", response_model=FindingResponse, tags=["Findings & Remediation"])
def update_finding(
    finding_id: str,
    update_data: FindingUpdate,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ENGINEER))
):
    """Updates finding lifecycle status or notes. Requires engineer or admin role."""
    try:
        return FindingService.update_finding(
            db=db,
            finding_id=finding_id,
            status=update_data.status,
            severity=update_data.severity,
            assigned_owner=update_data.assigned_owner,
            remediation_notes=update_data.remediation_notes,
            due_date=update_data.due_date
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/findings/{finding_id}/waiver", response_model=FindingResponse, tags=["Findings & Remediation"])
def apply_finding_risk_waiver(
    finding_id: str,
    waiver_data: FindingRiskWaiverRequest,
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ADMIN))
):
    """
    Formally records an authorized risk waiver / acceptance exception with expiration date.
    Restricted to Administrator role.
    """
    try:
        return FindingService.apply_risk_waiver(
            db=db,
            finding_id=finding_id,
            justification=waiver_data.justification,
            approved_by=waiver_data.approved_by,
            expires_at=waiver_data.expires_at,
            notes=waiver_data.notes
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ----------------- ASSESSMENTS & HISTORICAL AUDIT -----------------
@app.get("/api/v1/assessments", response_model=List[AssessmentRunResponse], tags=["Assessments"])
def list_assessments(
    limit: int = Query(20, le=100),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    return db.query(AssessmentRun).order_by(AssessmentRun.started_at.desc()).limit(limit).all()


# ----------------- MONITORED ASSETS -----------------
@app.get("/api/v1/assets", tags=["Assets"])
def list_assets(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Lists enterprise target assets, current network reachability, and historical evidence counts without leaking credentials."""
    return AssetService.list_monitored_assets(db)


# ----------------- REPORTS & AUDIT DOSSIER -----------------
@app.get("/api/v1/reports/summary", tags=["Reports"])
def get_audit_summary_report(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Generates an executive compliance and assurance dossier summary using the authoritative assurance service."""
    overview = AssuranceService.get_assurance_overview(db)
    ctrl = overview["controls"]
    return {
        "report_title": "Enterprise Security Assurance & Compliance Readiness Report",
        "generated_at_utc": overview["timestamp_utc"],
        "frameworks_evaluated": ["NIST SP 800-53 Rev 5", "ISO/IEC 27001:2022"],
        "control_coverage": {
            "catalog_total_controls": ctrl["catalog_total"],
            "total_controls": ctrl["total"], # Backward compatibility
            "controls_with_executable_tests": ctrl["executable_tested_count"],
            "controls_with_recorded_assessments": ctrl["scored_controls_count"],
            "verified_effective": ctrl["verified_effective"],
            "config_compliant_unverified": ctrl["config_compliant_unverified"],
            "deficient": ctrl["deficient"],
            "unknown_or_stale": ctrl["unknown"],
            "assurance_index_pct": ctrl["assurance_index_pct"],
            "assurance_index_assessed_pct": ctrl["assurance_index_assessed_pct"],
            "assurance_index_catalog_pct": ctrl["assurance_index_catalog_pct"],
            "denominator_basis": ctrl.get("denominator_basis", "Tested Controls")
        },
        "evidence_integrity": {
            "total_evidence_records": overview["evidence"]["total_records"],
            "ledger_chain_intact": overview["evidence"]["ledger_valid"],
            "violations_detected": overview["evidence"]["violations_count"]
        },
        "findings_summary": overview["findings"],
        "disclaimer": "This report summarizes automated assessment observations and does not constitute a formal third-party audit certification or attestation opinion."
    }


# ----------------- CRYPTOGRAPHIC LEDGER AUDITING -----------------
@app.get("/api/v1/ledger/verify", tags=["Evidence Vault"])
def verify_evidence_ledger(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """
    Auditor-defensible verification:
    Validates that every evidence payload's SHA-256 matches its content and the sequential hash chain is unbroken.
    """
    return LedgerService.verify_ledger(db)


@app.post("/api/v1/ledger/checkpoint", response_model=CheckpointArtifactSchema, tags=["Evidence Vault"])
def create_ledger_checkpoint(
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_ADMIN))
):
    """
    Creates and signs a canonical cryptographic checkpoint anchoring the current sequential hash-chain state.
    Restricted to administrative authorization.
    """
    try:
        return LedgerService.create_checkpoint(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate ledger checkpoint: {str(e)}")


@app.post("/api/v1/ledger/checkpoint/verify", response_model=CheckpointVerificationResponse, tags=["Evidence Vault"])
def verify_ledger_checkpoint(
    checkpoint: Dict[str, Any],
    public_key_pem: Optional[str] = Query(None, description="Optional external public key PEM override"),
    min_expected_sequence: Optional[int] = Query(None, description="Optional minimum expected sequence for rollback resistance"),
    db: Session = Depends(get_db),
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """
    Validates an external signed checkpoint:
    1. Verifies Ed25519 digital signature over canonical checkpoint payload using trusted public key.
    2. Confirms checkpoint hash matches local database record.
    3. Confirms unbroken sequential hash-chain continuity up to the checkpoint boundary.
    4. Detects truncation / database rollback attempts against min_expected_sequence.
    """
    return LedgerService.verify_checkpoint(
        db,
        checkpoint_data=checkpoint,
        public_key=public_key_pem,
        min_expected_sequence=min_expected_sequence
    )


# ----------------- CHAOS & DRIFT INJECTION -----------------
@app.get("/api/v1/chaos/catalog", tags=["Chaos Engine"])
def list_chaos_catalog(
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Lists all available security drift & regression scenarios."""
    return DRIFT_CATALOG


@app.get("/api/v1/chaos/active", tags=["Chaos Engine"])
def get_active_drifts(
    _: str = Depends(require_role(ROLE_AUDITOR))
):
    """Returns currently active drifts affecting the environment."""
    return ChaosInjector.list_active_drifts()


@app.post("/api/v1/chaos/inject/{drift_id}", tags=["Chaos Engine"])
def inject_chaos_drift(
    drift_id: str,
    mode: str = Query("SIMULATED", enum=["SIMULATED", "LIVE_LAB_MUTATION"]),
    _: str = Depends(require_role(ROLE_ADMIN))
):
    """
    Injects a compliance drift. Strictly restricted to administrative authorization.
    Never run live mutations without explicit supervisor clearance.
    """
    try:
        return ChaosInjector.inject_drift(drift_id, mode=mode)
    except ConnectionError as ce:
        raise HTTPException(status_code=503, detail=str(ce))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/chaos/experiment/{drift_id}", tags=["Chaos Engine"])
def run_chaos_drift_experiment(
    drift_id: str,
    mode: str = Query("SIMULATED", enum=["SIMULATED", "LIVE_LAB_MUTATION"]),
    _: str = Depends(require_role(ROLE_ADMIN))
):
    """
    Executes the complete 8-phase verifiable drift experiment:
    PRECHECK -> BASELINE_CAPTURED -> MUTATION_APPLIED -> MUTATION_VERIFIED ->
    ASSESSMENT_EXECUTED -> DETECTION_VERIFIED -> RESTORATION_EXECUTED -> RECOVERY_VERIFIED.
    Restricted to Administrator role.
    """
    try:
        return ChaosInjector.execute_full_lifecycle_experiment(drift_id, mode=mode)
    except ConnectionError as ce:
        raise HTTPException(status_code=503, detail=str(ce))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/chaos/restore", tags=["Chaos Engine"])
def restore_compliant_baseline(
    _: str = Depends(require_role(ROLE_ADMIN))
):
    """Clears all active drifts and restores the compliant baseline. Strictly restricted to administrative authorization."""
    return ChaosInjector.restore_baseline()
