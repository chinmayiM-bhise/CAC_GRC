"""
CAC-GRC Finding & Remediation Service.
Enforces finding deduplication, 4-stage lifecycle transitions:
OPEN -> IN_PROGRESS -> READY_FOR_RETEST -> VERIFIED_RESOLVED,
strict resolution gating requiring passing fresh assessments before findings can be closed,
and a formal auditable risk-waiver workflow with expiration dates.
"""

from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, text
import datetime

from app.models.finding import Finding
from app.models.score import EWCESScore
from app.models.evidence import EvidenceRecord
from app.models.base import utc_now
from app.engine.scoring.classifier import STATE_DEFICIENT, STATE_VERIFIED_EFFECTIVE, STATE_UNKNOWN


class FindingService:
    @staticmethod
    def list_findings(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        control_id: Optional[str] = None
    ) -> List[Finding]:
        query = db.query(Finding)
        if status:
            query = query.filter(Finding.status == status)
        if severity:
            query = query.filter(Finding.severity == severity)
        if control_id:
            query = query.filter(Finding.control_id == control_id)
        return query.order_by(Finding.created_at.desc()).all()

    @staticmethod
    def sync_finding(
        db: Session,
        control_id: str,
        test_id: str,
        severity: str,
        description: str,
        target_type: str = "LINUX_VM",
        target_host: Optional[str] = None,
        assigned_owner: str = "Security Engineering"
    ) -> Finding:
        """
        Deduplicates findings: If an active finding (OPEN, IN_PROGRESS, READY_FOR_RETEST) already exists
        for this control_id and test_id, updates its description, last_detected_at, and increments occurrence_count
        instead of creating duplicate clutter.
        """
        now = utc_now()
        active_finding = db.query(Finding).filter(
            Finding.control_id == control_id,
            Finding.status.in_(["OPEN", "IN_PROGRESS", "READY_FOR_RETEST", "IN_REMEDIATION"])
        ).first()

        if active_finding:
            active_finding.description = description
            active_finding.severity = severity
            active_finding.test_id = test_id
            active_finding.target_type = target_type
            if target_host:
                active_finding.target_host = target_host
            active_finding.occurrence_count = (active_finding.occurrence_count or 1) + 1
            active_finding.last_detected_at = now
            active_finding.updated_at = now
            db.commit()
            db.refresh(active_finding)
            return active_finding
        else:
            new_finding = Finding(
                control_id=control_id,
                test_id=test_id,
                target_type=target_type,
                target_host=target_host,
                severity=severity,
                status="OPEN",
                title=f"Non-Compliance: {control_id} Control Failure",
                description=description,
                assigned_owner=assigned_owner,
                occurrence_count=1,
                first_detected_at=now,
                last_detected_at=now
            )
            db.add(new_finding)
            db.commit()
            db.refresh(new_finding)
            return new_finding

    @staticmethod
    def resolve_findings_for_control(
        db: Session,
        control_id: str,
        notes: str = "Verified effective during automated assessment.",
        run_id: Optional[str] = None
    ):
        """
        Automatically resolves active findings when an assessment confirms the control is now VERIFIED_EFFECTIVE.
        """
        now = utc_now()
        active_findings = db.query(Finding).filter(
            Finding.control_id == control_id,
            Finding.status.in_(["OPEN", "IN_PROGRESS", "READY_FOR_RETEST", "IN_REMEDIATION"])
        ).all()

        for f in active_findings:
            f.status = "RESOLVED"
            f.resolved_at = now
            f.verified_resolved_at = now
            f.resolution_run_id = run_id
            f.remediation_notes = notes

        if active_findings:
            db.commit()

    @staticmethod
    def update_finding(
        db: Session,
        finding_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_owner: Optional[str] = None,
        remediation_notes: Optional[str] = None,
        due_date: Optional[Any] = None,
        enforce_fresh_pass: bool = True
    ) -> Finding:
        """
        Updates finding lifecycle.
        Supported statuses: OPEN, IN_PROGRESS, READY_FOR_RETEST, VERIFIED_RESOLVED (or RESOLVED), RISK_ACCEPTED.
        Strict Resolution Gating:
        - Transitioning to VERIFIED_RESOLVED or RESOLVED strictly requires that the underlying control's
          latest assessment is VERIFIED_EFFECTIVE with intact cryptographic integrity.
        """
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        resolved_target_statuses = ("VERIFIED_RESOLVED", "RESOLVED", "CLOSED")
        if status in resolved_target_statuses and enforce_fresh_pass:
            # Check latest score for this control (deterministic ordering even on sub-millisecond timestamps)
            is_sqlite = False
            try:
                bind = db.get_bind()
                is_sqlite = (bind.dialect.name == "sqlite")
            except Exception:
                pass
            order_clause = [EWCESScore.evaluated_at.desc(), text("rowid DESC")] if is_sqlite else [EWCESScore.evaluated_at.desc(), EWCESScore.created_at.desc(), EWCESScore.id.desc()]
            latest_score = db.query(EWCESScore).filter_by(
                control_id=finding.control_id
            ).order_by(*order_clause).first()

            if not latest_score:
                raise ValueError(
                    f"Cannot resolve finding {finding_id}: no assessment score found for control '{finding.control_id}'. "
                    f"A passing re-assessment is required before closing this finding."
                )

            if latest_score.state == STATE_DEFICIENT:
                raise ValueError(
                    f"Cannot resolve finding {finding_id}: underlying control '{finding.control_id}' "
                    f"is currently DEFICIENT (not VERIFIED_EFFECTIVE). A passing re-assessment is required before closing this finding."
                )

            if latest_score.state != STATE_VERIFIED_EFFECTIVE:
                raise ValueError(
                    f"Cannot resolve finding {finding_id}: underlying control '{finding.control_id}' "
                    f"is currently in state '{latest_score.state}' (not VERIFIED_EFFECTIVE). "
                    f"A passing re-assessment is required before closing this finding."
                )

            if not latest_score.hash_integrity_verified:
                raise ValueError(
                    f"Cannot resolve finding {finding_id}: latest assessment for control '{finding.control_id}' "
                    f"failed cryptographic hash integrity verification."
                )

            if (latest_score.freshness_score or 0.0) <= 0.0:
                raise ValueError(
                    f"Cannot resolve finding {finding_id}: assessment evidence for control '{finding.control_id}' "
                    f"has expired past its TTL boundary (freshness = 0.0). Fresh re-assessment required."
                )

            # Check latest test evidence if recorded
            if finding.test_id:
                latest_ev = db.query(EvidenceRecord).filter_by(
                    test_id=finding.test_id
                ).order_by(EvidenceRecord.created_at.desc(), EvidenceRecord.id.desc()).first()
                if latest_ev and latest_ev.result_code != 1:
                    raise ValueError(
                        f"Cannot resolve finding {finding_id}: latest evidence for test '{finding.test_id}' "
                        f"does not report an active pass (result_code = {latest_ev.result_code}). Re-test required."
                    )

            now = utc_now()
            finding.resolved_at = now
            finding.verified_resolved_at = now
            # Canonicalize status: preserve RESOLVED if explicitly requested, otherwise VERIFIED_RESOLVED
            if status not in ("RESOLVED", "VERIFIED_RESOLVED"):
                status = "VERIFIED_RESOLVED"

        elif status == "RISK_ACCEPTED":
            if not remediation_notes or len(remediation_notes.strip()) < 10:
                raise ValueError(
                    f"Risk acceptance for finding {finding_id} requires detailed justification notes (minimum 10 characters) "
                    f"documenting the business exception, mitigating controls, and approving authority."
                )
            remediation_notes = f"[RISK ACCEPTED - OPERATIONAL EXCEPTION]: {remediation_notes.strip()}"
            finding.resolved_at = None

        if status is not None:
            finding.status = status
        if severity is not None:
            finding.severity = severity
        if assigned_owner is not None:
            finding.assigned_owner = assigned_owner
        if remediation_notes is not None:
            finding.remediation_notes = remediation_notes
        if due_date is not None:
            finding.due_date = due_date

        finding.updated_at = utc_now()
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    def apply_risk_waiver(
        db: Session,
        finding_id: str,
        justification: str,
        approved_by: str,
        expires_at: datetime.datetime,
        notes: Optional[str] = None
    ) -> Finding:
        """
        Formal auditable risk waiver workflow.
        Attaches business justification, approving authority, and mandatory expiration date.
        """
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        if len(justification.strip()) < 10:
            raise ValueError("Risk waiver justification must be at least 10 characters.")

        finding.status = "RISK_ACCEPTED"
        finding.risk_waiver_justification = justification.strip()
        finding.risk_waiver_approved_by = approved_by.strip()
        finding.risk_waiver_expires_at = expires_at
        waiver_note = f"[RISK WAIVER GRANTED by {approved_by} until {expires_at.date().isoformat()}]: {justification}"
        if notes:
            waiver_note += f" | {notes}"
        finding.remediation_notes = waiver_note
        finding.updated_at = utc_now()
        db.commit()
        db.refresh(finding)
        return finding
