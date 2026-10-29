import datetime
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.test_definition import TestDefinition
from app.models.evidence import EvidenceRecord
from app.models.score import EWCESScore
from app.models.finding import Finding
from app.models.base import utc_now
from app.engine.scoring.decay import calculate_evidence_freshness, ensure_utc
from app.engine.ledger.hasher import compute_evidence_hash

# The Four Canonical Assurance States
STATE_VERIFIED_EFFECTIVE = "VERIFIED_EFFECTIVE"
STATE_CONFIG_COMPLIANT_UNVERIFIED = "CONFIG_COMPLIANT_EFFECTIVENESS_UNVERIFIED"
STATE_DEFICIENT = "DEFICIENT"
STATE_UNKNOWN = "UNKNOWN"


class EWCESClassifier:
    """
    Evidence-Weighted Control Effectiveness Scoring (EW-CES) Engine.
    Evaluates an authoritative framework control into an explainable 4-state assurance model:
    - VERIFIED_EFFECTIVE: All required Tier 1 (config) and Tier 2 (behavioral) checks have fresh,
      live target evidence with valid cryptographic hashes.
    - CONFIG_COMPLIANT_EFFECTIVENESS_UNVERIFIED: Static configuration verified compliant on live target,
      but behavioral effectiveness is absent, stale past TTL, incomplete, or simulated.
    - DEFICIENT: One or more required checks have confirmed operational failures at runtime.
    - UNKNOWN: Evidence is missing, stale past TTL, untrusted (tampered ledger), or affected by
      target connection/execution errors.
    """

    @classmethod
    def evaluate_control(cls, db: Session, control_id: str, now: Optional[datetime.datetime] = None) -> EWCESScore:
        current_time = ensure_utc(now) or utc_now()

        # 1. Fetch all mappings for this control
        mappings = db.query(PolicyMapping).filter_by(control_id=control_id).all()
        mapping_ids = [m.id for m in mappings]

        # Check if control requires organizational/manual evidence rather than technical test
        control = db.query(FrameworkControl).filter_by(control_id=control_id).first()
        if control and getattr(control, "assessment_method", None) == "ORGANIZATIONAL_MANUAL":
            if not mapping_ids:
                summary = f"Organizational/procedural control '{control_id}' requires policy mapping and documentary evidence; no policies currently mapped."
            else:
                summary = f"Organizational/procedural control '{control_id}' requires manual governance audit or documentary evidence; no automated technical test applicable."
            return cls._create_score(
                db=db,
                control_id=control_id,
                state=STATE_UNKNOWN,
                freshness=1.0 if mapping_ids else 0.0,
                has_tier2=False,
                hash_valid=True,
                evaluated_at=current_time,
                summary=summary,
                metadata={"assessment_method": "ORGANIZATIONAL_MANUAL", "mapped_policies_count": len(mapping_ids)}
            )

        if not mapping_ids:
            return cls._create_score(
                db=db,
                control_id=control_id,
                state=STATE_UNKNOWN,
                freshness=0.0,
                has_tier2=False,
                hash_valid=True,
                evaluated_at=current_time,
                summary=f"No approved policy mappings configured for control {control_id}."
            )

        # 2. Fetch all test definitions for these mappings
        test_defs = db.query(TestDefinition).filter(TestDefinition.mapping_id.in_(mapping_ids)).all()
        if not test_defs:
            return cls._create_score(
                db=db,
                control_id=control_id,
                state=STATE_UNKNOWN,
                freshness=0.0,
                has_tier2=False,
                hash_valid=True,
                evaluated_at=current_time,
                summary=f"Policy mapping exists, but no Compliance-as-Code tests are bound to {control_id}."
            )

        # 3. Partition required tests into Tier 1 (config) and Tier 2 (behavioral)
        required_tests = [t for t in test_defs if getattr(t, 'is_required', True)]
        required_t1_tests = [t for t in required_tests if not (getattr(t, 'is_behavioral', False) or t.tier == 2)]
        required_t2_tests = [t for t in required_tests if (getattr(t, 'is_behavioral', False) or t.tier == 2)]
        behavioral_required = len(required_t2_tests) > 0

        failed_test_ids = []
        integrity_failed_tests = []
        execution_error_test_ids = []
        missing_or_stale_t1_ids = []
        missing_or_stale_t2_ids = []

        passed_live_t1_ids = set()
        passed_sim_t1_ids = set()
        passed_live_t2_ids = set()
        passed_sim_t2_ids = set()

        freshness_values = []
        subtest_breakdown = []

        for tdef in test_defs:
            is_behavioral = getattr(tdef, 'is_behavioral', False) or tdef.tier == 2
            is_required = getattr(tdef, 'is_required', True)

            # Query the newest evidence record for this test
            latest_ev = db.query(EvidenceRecord).filter_by(
                test_id=tdef.test_id
            ).order_by(EvidenceRecord.created_at.desc(), EvidenceRecord.id.desc()).first()

            if not latest_ev:
                if is_required:
                    if is_behavioral:
                        missing_or_stale_t2_ids.append(tdef.test_id)
                    else:
                        missing_or_stale_t1_ids.append(tdef.test_id)

                subtest_breakdown.append({
                    "test_id": tdef.test_id,
                    "tier": tdef.tier,
                    "is_required": is_required,
                    "is_behavioral": is_behavioral,
                    "status": "MISSING_EVIDENCE",
                    "freshness": 0.0,
                    "provenance": "NONE"
                })
                continue

            # Verify cryptographic digest before trusting evidence
            expected_hash = compute_evidence_hash(
                test_id=latest_ev.test_id,
                collected_at_iso=ensure_utc(latest_ev.collected_at).isoformat(),
                result_code=latest_ev.result_code,
                raw_telemetry=latest_ev.raw_telemetry
            )
            hash_ok = (expected_hash == latest_ev.payload_sha256)
            if not hash_ok:
                integrity_failed_tests.append(tdef.test_id)

            # Compute freshness with exact TTL boundary math
            freshness = calculate_evidence_freshness(latest_ev.collected_at, tdef.max_ttl_hours, current_time)
            freshness_values.append(freshness)
            is_fresh = (freshness > 0.0)

            if is_required and not is_fresh:
                if is_behavioral:
                    missing_or_stale_t2_ids.append(tdef.test_id)
                else:
                    missing_or_stale_t1_ids.append(tdef.test_id)

            # Execution error / host unreachable
            if latest_ev.result_code == 0:
                if is_required:
                    execution_error_test_ids.append(tdef.test_id)
                subtest_breakdown.append({
                    "test_id": tdef.test_id,
                    "tier": tdef.tier,
                    "is_required": is_required,
                    "is_behavioral": is_behavioral,
                    "status": "EXECUTION_ERROR",
                    "execution_status": getattr(latest_ev, 'execution_status', 'UNKNOWN'),
                    "provenance": getattr(latest_ev, 'evidence_provenance', 'LIVE_TARGET'),
                    "freshness": freshness,
                    "hash_valid": hash_ok
                })

            # Confirmed operational failure
            elif latest_ev.result_code == -1:
                if is_required and hash_ok:
                    failed_test_ids.append(tdef.test_id)
                subtest_breakdown.append({
                    "test_id": tdef.test_id,
                    "tier": tdef.tier,
                    "is_required": is_required,
                    "is_behavioral": is_behavioral,
                    "status": "FAILED",
                    "provenance": getattr(latest_ev, 'evidence_provenance', 'LIVE_TARGET'),
                    "freshness": freshness,
                    "hash_valid": hash_ok
                })

            # Confirmed pass
            elif latest_ev.result_code == 1:
                prov = getattr(latest_ev, 'evidence_provenance', 'LIVE_TARGET')
                is_live = (prov == "LIVE_TARGET")

                if is_fresh and hash_ok:
                    if is_behavioral:
                        if is_live:
                            passed_live_t2_ids.add(tdef.test_id)
                        else:
                            passed_sim_t2_ids.add(tdef.test_id)
                    else:
                        if is_live:
                            passed_live_t1_ids.add(tdef.test_id)
                        else:
                            passed_sim_t1_ids.add(tdef.test_id)

                subtest_breakdown.append({
                    "test_id": tdef.test_id,
                    "tier": tdef.tier,
                    "is_required": is_required,
                    "is_behavioral": is_behavioral,
                    "status": "PASSED" if is_fresh else "STALE_PASS",
                    "provenance": prov,
                    "freshness": freshness,
                    "hash_valid": hash_ok
                })

        avg_freshness = round(sum(freshness_values) / len(freshness_values), 4) if freshness_values else 0.0

        # Tier Coverage Accounting
        all_required_t1_passed_live = len(required_t1_tests) > 0 and all(t.test_id in passed_live_t1_ids for t in required_t1_tests)
        has_simulated_t1 = any(t.test_id in passed_sim_t1_ids for t in required_t1_tests)

        all_required_t2_passed_live = behavioral_required and all(t.test_id in passed_live_t2_ids for t in required_t2_tests)
        has_simulated_t2 = any(t.test_id in passed_sim_t2_ids for t in required_t2_tests)

        has_integrity_failure = len(integrity_failed_tests) > 0

        # 4. Strict Precedence Resolution
        # Precedence 1: Tampered Evidence on Sequential Hash Chain
        if has_integrity_failure:
            state = STATE_UNKNOWN
            summary = f"CRITICAL: Evidence hash mismatch on tests {integrity_failed_tests}. Sequential hash-linked ledger integrity compromised."

        # Precedence 2: Confirmed Failure on Required Test
        elif failed_test_ids:
            state = STATE_DEFICIENT
            summary = f"Confirmed operational failure on required security test(s): {', '.join(failed_test_ids)}."
            if missing_or_stale_t1_ids or missing_or_stale_t2_ids:
                summary += f" [Note: Additional evidence exhibits temporal decay past TTL on {', '.join(missing_or_stale_t1_ids + missing_or_stale_t2_ids)}]."
            cls._sync_finding(db, control_id, failed_test_ids[0], "HIGH", summary)

        # Precedence 3: Target Connection Failure / Execution Error on any Required Test
        elif execution_error_test_ids:
            state = STATE_UNKNOWN
            summary = f"Assessment incomplete: Target connection failed or execution errored on {', '.join(execution_error_test_ids)}. Host may be offline or unreachable."

        # Precedence 4: Missing or Stale Configuration Evidence
        elif missing_or_stale_t1_ids:
            state = STATE_UNKNOWN
            summary = f"Required configuration evidence is missing or stale past TTL on: {', '.join(missing_or_stale_t1_ids)}."

        # Precedence 5: Configuration Evidence is Simulated (Cannot establish live configuration compliance)
        elif has_simulated_t1 and not all_required_t1_passed_live:
            state = STATE_UNKNOWN
            summary = "Configuration checks passed via SIMULATED_LAB evidence. Live target inspection required to verify control assurance."

        # Precedence 6: Verified Effective (All required config passed live AND all required behavioral passed live)
        elif all_required_t1_passed_live and (all_required_t2_passed_live or not behavioral_required):
            state = STATE_VERIFIED_EFFECTIVE
            summary = "All required configuration checks passed and behavioral effectiveness verified with fresh, live, integrity-checked evidence."
            cls._resolve_finding(db, control_id)

        # Precedence 7: Config Compliant Only (Behavioral probe missing, stale, incomplete, or simulated)
        elif all_required_t1_passed_live:
            state = STATE_CONFIG_COMPLIANT_UNVERIFIED
            if has_simulated_t2:
                summary = "Configuration verified compliant on live target, but behavioral challenge testing was SIMULATED. Live behavioral verification required for VERIFIED_EFFECTIVE."
            else:
                summary = "Configuration verified compliant on live target, but behavioral effectiveness testing is absent, stale, or incomplete."

        else:
            state = STATE_UNKNOWN
            summary = "Telemetry insufficient to determine control assurance state."

        return cls._create_score(
            db=db,
            control_id=control_id,
            state=state,
            freshness=avg_freshness,
            has_tier2=all_required_t2_passed_live,
            hash_valid=(not has_integrity_failure),
            evaluated_at=current_time,
            summary=summary,
            metadata={
                "subtests": subtest_breakdown,
                "behavioral_required": behavioral_required,
                "required_tier1_count": len(required_t1_tests),
                "required_tier2_count": len(required_t2_tests),
                "all_required_t1_passed_live": all_required_t1_passed_live,
                "all_required_t2_passed_live": all_required_t2_passed_live,
                "has_simulated_evidence": has_simulated_t1 or has_simulated_t2,
                "rule_version": "EW-CES-2.1"
            }
        )

    @classmethod
    def evaluate_all(cls, db: Session) -> List[EWCESScore]:
        """Evaluates EW-CES scores across all framework controls."""
        controls = db.query(FrameworkControl).all()
        scores = []
        for ctrl in controls:
            score = cls.evaluate_control(db, ctrl.control_id)
            scores.append(score)
        return scores

    @staticmethod
    def _create_score(db: Session, control_id: str, state: str, freshness: float,
                      has_tier2: bool, hash_valid: bool, evaluated_at: datetime.datetime,
                      summary: str, metadata: dict = None) -> EWCESScore:
        score = EWCESScore(
            control_id=control_id,
            state=state,
            freshness_score=freshness,
            has_tier2_evidence=has_tier2,
            hash_integrity_verified=hash_valid,
            evaluated_at=evaluated_at,
            diagnostic_summary=summary,
            evaluation_metadata=metadata or {}
        )
        db.add(score)
        db.commit()
        db.refresh(score)
        return score

    @staticmethod
    def _sync_finding(db: Session, control_id: str, test_id: str, severity: str, description: str):
        """Automatically maintains or opens a Finding when a control is DEFICIENT via FindingService."""
        from app.services.finding_service import FindingService
        FindingService.sync_finding(db, control_id, test_id, severity, description)

    @staticmethod
    def _resolve_finding(db: Session, control_id: str):
        """Resolves active findings when a control returns to VERIFIED_EFFECTIVE via FindingService."""
        from app.services.finding_service import FindingService
        FindingService.resolve_findings_for_control(db, control_id)
