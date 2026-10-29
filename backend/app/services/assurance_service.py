"""
CAC-GRC Assurance & Metrics Service.
Centralized authority for computing EW-CES 4-state assurance summaries,
coverage indices, freshness metrics, and control scoring.
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.framework import FrameworkControl
from app.models.score import EWCESScore
from app.models.finding import Finding
from app.models.evidence import EvidenceRecord
from app.models.test_definition import TestDefinition
from app.models.policy import Policy
from app.models.chaos import ChaosDriftRecord
from app.engine.scoring.classifier import (
    EWCESClassifier,
    STATE_VERIFIED_EFFECTIVE,
    STATE_CONFIG_COMPLIANT_UNVERIFIED,
    STATE_DEFICIENT,
    STATE_UNKNOWN
)
from app.engine.ledger.vault import EvidenceVault
from app.models.base import utc_now


class AssuranceService:
    @staticmethod
    def get_latest_control_scores(db: Session, framework: Optional[str] = None) -> List[EWCESScore]:
        """
        Returns the latest EWCESScore for every framework control,
        optionally filtered by framework name.
        """
        # Subquery for maximum evaluated_at per control_id
        subq = db.query(
            EWCESScore.control_id,
            func.max(EWCESScore.evaluated_at).label("max_eval")
        ).group_by(EWCESScore.control_id).subquery()

        query = db.query(EWCESScore).join(
            subq,
            (EWCESScore.control_id == subq.c.control_id) &
            (EWCESScore.evaluated_at == subq.c.max_eval)
        )

        if framework:
            query = query.join(
                FrameworkControl,
                FrameworkControl.control_id == EWCESScore.control_id
            ).filter(FrameworkControl.framework_name == framework)

        return query.all()

    @classmethod
    def get_assurance_overview(cls, db: Session) -> Dict[str, Any]:
        """
        Calculates authoritative platform-wide assurance metrics.
        This provides a single source of truth for both REST APIs and UI cards.
        """
        controls = db.query(FrameworkControl).all()
        total_controls = len(controls)

        latest_scores = cls.get_latest_control_scores(db)
        score_by_ctrl = {s.control_id: s for s in latest_scores}

        ve_count = 0
        cc_count = 0
        def_count = 0
        freshness_sum = 0.0

        for ctrl in controls:
            s = score_by_ctrl.get(ctrl.control_id)
            if s:
                freshness_sum += (s.freshness_score or 0.0)
                if s.state == STATE_VERIFIED_EFFECTIVE:
                    ve_count += 1
                elif s.state == STATE_CONFIG_COMPLIANT_UNVERIFIED:
                    cc_count += 1
                elif s.state == STATE_DEFICIENT:
                    def_count += 1

        # Controls with automated test definitions
        from app.models.mapping import PolicyMapping
        test_defs = db.query(TestDefinition).all()
        test_mapping_ids = {t.mapping_id for t in test_defs if t.mapping_id}
        tested_controls = {
            m.control_id for m in db.query(PolicyMapping).filter(PolicyMapping.id.in_(test_mapping_ids)).all()
        } if test_mapping_ids else set()
        tested_controls_count = len(tested_controls)
        scored_controls_count = len(score_by_ctrl)

        # Controls with no score or state == UNKNOWN
        unk_count = total_controls - (ve_count + cc_count + def_count)
        avg_freshness = round(freshness_sum / total_controls, 3) if total_controls > 0 else 0.0
        
        # Mathematical indices with documented denominators
        assurance_index_catalog = round((ve_count / total_controls * 100), 1) if total_controls > 0 else 0.0
        assessed_denom = tested_controls_count if tested_controls_count > 0 else (scored_controls_count if scored_controls_count > 0 else total_controls)
        assurance_index_assessed = round((ve_count / assessed_denom * 100), 1) if assessed_denom > 0 else 0.0

        # Findings breakdown (all active remediation statuses)
        open_findings = db.query(Finding).filter(Finding.status.in_(["OPEN", "IN_PROGRESS", "READY_FOR_RETEST", "IN_REMEDIATION"])).all()
        findings_by_severity = {
            "CRITICAL": sum(1 for f in open_findings if f.severity == "CRITICAL"),
            "HIGH": sum(1 for f in open_findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in open_findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in open_findings if f.severity == "LOW")
        }

        # Ledger status
        ledger_valid, violations = EvidenceVault.verify_ledger_integrity(db)
        total_evidence = db.query(EvidenceRecord).count()

        # Active Drifts
        active_drifts_count = db.query(ChaosDriftRecord).filter_by(status="ACTIVE").count()

        return {
            "timestamp_utc": utc_now().isoformat(),
            "controls": {
                "total": total_controls,
                "catalog_total": total_controls,
                "executable_tested_count": tested_controls_count,
                "scored_controls_count": scored_controls_count,
                "verified_effective": ve_count,
                "config_compliant_unverified": cc_count,
                "deficient": def_count,
                "unknown": unk_count,
                "assurance_index_pct": assurance_index_catalog, # Preserves backward compatibility for test_services.py
                "assurance_index_assessed_pct": assurance_index_assessed,
                "assurance_index_catalog_pct": assurance_index_catalog,
                "denominator_basis": f"Evaluated against {assessed_denom} controls with executable CaC tests (Catalog: {total_controls})"
            },
            "evidence": {
                "total_records": total_evidence,
                "average_freshness": avg_freshness,
                "ledger_valid": ledger_valid,
                "violations_count": len(violations)
            },
            "findings": {
                "total_open": len(open_findings),
                "by_severity": findings_by_severity
            },
            "inventory": {
                "policies_count": db.query(Policy).count(),
                "tests_count": db.query(TestDefinition).count(),
                "tier1_tests_count": db.query(TestDefinition).filter_by(tier=1).count(),
                "tier2_tests_count": db.query(TestDefinition).filter_by(tier=2).count()
            },
            "chaos": {
                "active_drifts": active_drifts_count
            }
        }

    @staticmethod
    def reevaluate_all(db: Session) -> List[EWCESScore]:
        """Re-evaluates EW-CES states across all controls and saves results."""
        return EWCESClassifier.evaluate_all(db)
