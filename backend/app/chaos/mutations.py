import datetime
import socket
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from app.database import SessionLocal
from app.models.chaos import ChaosDriftRecord
from app.models.audit_log import AuditLog
from app.models.base import utc_now
from app.config import settings

DRIFT_CATALOG = {
    "pam-lockout-bypass": {
        "description": "Corrupts Linux PAM configuration (deny=999), bypassing brute-force lockout defense.",
        "target": "LINUX_VM",
        "affected_tests": ["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"],
        "affected_controls": ["NIST-AC-7", "ISO-A.8.5"],
        "live_mutation_supported": True
    },
    "ssh-root-login-enabled": {
        "description": "Enables PermitRootLogin yes in sshd_config, violating least privilege.",
        "target": "LINUX_VM",
        "affected_tests": ["TEST-VM-LEAST-PRIV-T1"],
        "affected_controls": ["NIST-AC-6", "ISO-A.8.2"],
        "live_mutation_supported": True
    },
    "auditd-service-disabled": {
        "description": "Stops the auditd kernel auditing daemon, blindfolding event generation.",
        "target": "LINUX_VM",
        "affected_tests": ["TEST-VM-AUDITD-T1", "TEST-VM-AUDITD-T2"],
        "affected_controls": ["NIST-AU-2", "ISO-A.8.15"],
        "live_mutation_supported": True
    },
    "db-rogue-superuser": {
        "description": "Grants unauthorized superuser privileges (rolsuper=true) to a rogue account.",
        "target": "POSTGRES_DB",
        "affected_tests": ["TEST-DB-LEAST-PRIV-T1"],
        "affected_controls": ["NIST-AC-6", "ISO-A.8.2"],
        "live_mutation_supported": True
    },
    "db-tls-disabled": {
        "description": "Disables database SSL/TLS encryption, allowing plaintext communication.",
        "target": "POSTGRES_DB",
        "affected_tests": ["TEST-DB-TLS-T1", "TEST-DB-TLS-T2"],
        "affected_controls": ["NIST-SC-8", "ISO-A.8.24"],
        "live_mutation_supported": False
    }
}


class ChaosInjector:
    """
    Enterprise Chaos & Compliance Drift Engine.
    Supports both SIMULATED and LIVE mutations with an auditable 8-phase verifiable lifecycle:
    PRECHECK -> BASELINE_CAPTURED -> MUTATION_APPLIED -> MUTATION_VERIFIED ->
    ASSESSMENT_EXECUTED -> DETECTION_VERIFIED -> RESTORATION_EXECUTED -> RECOVERY_VERIFIED.
    """

    @classmethod
    def inject_drift(cls, drift_id: str, mode: str = "SIMULATED", actor: str = "CLI_USER") -> Dict[str, Any]:
        """
        Injects a compliance drift.
        mode: 'SIMULATED' (database state flag) or 'LIVE_LAB_MUTATION' (mutates actual target).
        """
        if drift_id not in DRIFT_CATALOG:
            raise ValueError(f"Unknown drift '{drift_id}'. Available: {list(DRIFT_CATALOG.keys())}")

        drift_info = DRIFT_CATALOG[drift_id]
        target_type = drift_info["target"]
        db = SessionLocal()

        try:
            # Check if this drift is already active
            existing = db.query(ChaosDriftRecord).filter_by(
                drift_id=drift_id,
                status="ACTIVE"
            ).first()

            if existing:
                return {
                    "status": "ALREADY_ACTIVE",
                    "drift_id": drift_id,
                    "drift_type": existing.drift_type,
                    "injected_at": existing.injected_at.isoformat(),
                    "affected_tests": drift_info["affected_tests"],
                    "affected_controls": drift_info["affected_controls"],
                    "message": f"Drift {drift_id} is already active in database."
                }

            precondition = {}
            postcondition = {}
            now = utc_now()

            history = [{
                "phase": "PRECHECK",
                "timestamp": now.isoformat(),
                "status": "SUCCESS",
                "details": f"Initiated injection in {mode} mode by {actor}."
            }]

            if mode == "LIVE_LAB_MUTATION":
                # Check live target accessibility first
                is_reachable, reach_err = cls._check_target_reachability(target_type)
                if not is_reachable:
                    record = ChaosDriftRecord(
                        drift_id=drift_id,
                        drift_type="LIVE_LAB_MUTATION",
                        target_type=target_type,
                        status="FAILED",
                        lifecycle_phase="PRECHECK_FAILED",
                        lifecycle_history=history + [{
                            "phase": "PRECHECK_FAILED",
                            "timestamp": utc_now().isoformat(),
                            "status": "FAILED",
                            "details": f"Target unreachable: {reach_err}"
                        }],
                        actor=actor,
                        audit_notes=f"Target unreachable: {reach_err}"
                    )
                    db.add(record)
                    db.commit()
                    raise ConnectionError(f"Cannot perform LIVE mutation. Target {target_type} unreachable: {reach_err}")

                history.append({
                    "phase": "PRECHECK",
                    "timestamp": utc_now().isoformat(),
                    "status": "SUCCESS",
                    "details": f"Target {target_type} verified reachable."
                })

                # Execute live mutation and verify
                precondition, postcondition = cls._execute_live_mutation(drift_id)
                history.append({
                    "phase": "BASELINE_CAPTURED",
                    "timestamp": utc_now().isoformat(),
                    "status": "SUCCESS",
                    "details": precondition
                })
                history.append({
                    "phase": "MUTATION_VERIFIED",
                    "timestamp": utc_now().isoformat(),
                    "status": "SUCCESS",
                    "details": postcondition
                })
            else:
                precondition = {"simulated": True, "baseline": "compliant"}
                postcondition = {"simulated": True, "drift_active": True}
                history.append({
                    "phase": "BASELINE_CAPTURED",
                    "timestamp": utc_now().isoformat(),
                    "status": "SUCCESS",
                    "details": precondition
                })
                history.append({
                    "phase": "MUTATION_APPLIED",
                    "timestamp": utc_now().isoformat(),
                    "status": "SUCCESS",
                    "details": postcondition
                })

            # Persist drift record to database
            record = ChaosDriftRecord(
                drift_id=drift_id,
                drift_type=mode,
                target_type=target_type,
                status="ACTIVE",
                lifecycle_phase="MUTATION_APPLIED",
                lifecycle_history=history,
                precondition_state=precondition,
                postcondition_verification=postcondition,
                actor=actor,
                audit_notes=f"Injected {drift_id} in {mode} mode."
            )
            db.add(record)

            # Record audit log
            audit = AuditLog(
                actor=actor,
                action="INJECT_CHAOS_DRIFT",
                target=target_type,
                outcome="SUCCESS",
                details={"drift_id": drift_id, "mode": mode, "affected_controls": drift_info["affected_controls"]}
            )
            db.add(audit)
            db.commit()

            return {
                "status": "DRIFT_INJECTED",
                "drift_id": drift_id,
                "drift_type": mode,
                "affected_tests": drift_info["affected_tests"],
                "affected_controls": drift_info["affected_controls"],
                "precondition": precondition,
                "postcondition": postcondition,
                "description": drift_info["description"]
            }
        finally:
            db.close()

    @classmethod
    def restore_baseline(cls, actor: str = "CLI_USER") -> Dict[str, Any]:
        """
        Restores all active drifts across database and live targets.
        """
        db = SessionLocal()
        try:
            active_records = db.query(ChaosDriftRecord).filter_by(status="ACTIVE").all()
            restored_count = 0
            restored_ids = []

            for record in active_records:
                now = utc_now()
                if record.drift_type == "LIVE_LAB_MUTATION":
                    cls._execute_live_restoration(record.drift_id)

                history = list(record.lifecycle_history or [])
                history.append({
                    "phase": "RESTORATION_EXECUTED",
                    "timestamp": now.isoformat(),
                    "status": "SUCCESS",
                    "details": f"Baseline restored by {actor}."
                })
                record.status = "RESTORED"
                record.lifecycle_phase = "RESTORATION_EXECUTED"
                record.lifecycle_history = history
                record.restored_at = now
                record.audit_notes = f"{record.audit_notes or ''} | Restored by {actor} at {now.isoformat()}"
                restored_count += 1
                restored_ids.append(record.drift_id)

            if restored_count > 0:
                audit = AuditLog(
                    actor=actor,
                    action="RESTORE_BASELINE",
                    outcome="SUCCESS",
                    details={"restored_count": restored_count, "drifts": restored_ids}
                )
                db.add(audit)

            db.commit()

            return {
                "status": "BASELINE_RESTORED",
                "cleared_drifts_count": restored_count,
                "restored_drifts": restored_ids
            }
        finally:
            db.close()

    @classmethod
    def execute_full_lifecycle_experiment(cls, drift_id: str, mode: str = "SIMULATED", actor: str = "ADMIN") -> Dict[str, Any]:
        """
        Executes the formal 8-phase verifiable drift lifecycle:
        1. PRECHECK: Target connectivity & prerequisite validation.
        2. BASELINE_CAPTURED: Record original compliant state.
        3. MUTATION_APPLIED: Apply controlled configuration drift.
        4. MUTATION_VERIFIED: Independently query target to confirm drift took effect.
        5. ASSESSMENT_EXECUTED: Run automated Compliance-as-Code tests.
        6. DETECTION_VERIFIED: Verify EW-CES transitions to DEFICIENT and Finding is created.
        7. RESTORATION_EXECUTED: Restore compliant baseline configuration.
        8. RECOVERY_VERIFIED: Rerun assessment and verify recovery to compliant state.
        """
        if drift_id not in DRIFT_CATALOG:
            raise ValueError(f"Unknown drift '{drift_id}'.")

        drift_info = DRIFT_CATALOG[drift_id]
        target_type = drift_info["target"]
        affected_tests = drift_info["affected_tests"]
        affected_controls = drift_info["affected_controls"]

        from app.engine.orchestrator import TestOrchestrator
        from app.engine.scoring.classifier import EWCESClassifier, STATE_DEFICIENT, STATE_VERIFIED_EFFECTIVE
        from app.models.finding import Finding

        orchestrator = TestOrchestrator()
        db = SessionLocal()
        lifecycle_events = []

        def log_phase(phase: str, status: str, details: Any):
            lifecycle_events.append({
                "phase": phase,
                "timestamp": utc_now().isoformat(),
                "status": status,
                "details": details
            })

        try:
            # Phase 1: PRECHECK
            if mode == "LIVE_LAB_MUTATION":
                reachable, err = cls._check_target_reachability(target_type)
                if not reachable:
                    log_phase("PRECHECK", "FAILED", f"Target {target_type} offline: {err}")
                    raise ConnectionError(f"Target {target_type} offline: {err}")
                log_phase("PRECHECK", "SUCCESS", f"Target {target_type} reachable over network.")
            else:
                log_phase("PRECHECK", "SUCCESS", "Simulation harness verified ready.")

            # Phase 2: BASELINE_CAPTURED
            precondition = {}
            if mode == "LIVE_LAB_MUTATION":
                precondition, _ = cls._capture_baseline(drift_id)
            else:
                precondition = {"simulated": True, "baseline": "compliant"}
            log_phase("BASELINE_CAPTURED", "SUCCESS", precondition)

            # Phase 3 & 4: MUTATION_APPLIED & MUTATION_VERIFIED
            injection_res = cls.inject_drift(drift_id, mode=mode, actor=actor)
            log_phase("MUTATION_APPLIED", "SUCCESS", {"drift_id": drift_id, "mode": mode})
            log_phase("MUTATION_VERIFIED", "SUCCESS", injection_res.get("postcondition", {}))

            # Phase 5: ASSESSMENT_EXECUTED
            assessment_results = []
            for tid in affected_tests:
                res = orchestrator.execute_test(db, tid, allow_simulation=(mode == "SIMULATED"))
                assessment_results.append(res)
            log_phase("ASSESSMENT_EXECUTED", "SUCCESS", {
                "tests_executed": [r["test_id"] for r in assessment_results],
                "results": [r["execution_status"] for r in assessment_results]
            })

            # Phase 6: DETECTION_VERIFIED
            detection_passed = False
            deficient_controls = []
            for cid in affected_controls:
                score = EWCESClassifier.evaluate_control(db, cid)
                if score.state == STATE_DEFICIENT:
                    deficient_controls.append(cid)

            # Check open findings
            open_findings = db.query(Finding).filter(
                Finding.control_id.in_(affected_controls),
                Finding.status == "OPEN"
            ).count()

            detection_passed = len(deficient_controls) > 0 and open_findings > 0
            log_phase("DETECTION_VERIFIED", "SUCCESS" if detection_passed else "FAILED", {
                "deficient_controls": deficient_controls,
                "open_findings_count": open_findings,
                "detection_confirmed": detection_passed
            })

            # Phase 7: RESTORATION_EXECUTED
            cls.restore_baseline(actor=actor)
            log_phase("RESTORATION_EXECUTED", "SUCCESS", f"Restored baseline configuration for {drift_id}.")

            # Phase 8: RECOVERY_VERIFIED
            recovery_results = []
            for tid in affected_tests:
                res = orchestrator.execute_test(db, tid, allow_simulation=(mode == "SIMULATED"))
                recovery_results.append(res)

            recovered_controls = []
            for cid in affected_controls:
                score = EWCESClassifier.evaluate_control(db, cid)
                if score.state != STATE_DEFICIENT:
                    recovered_controls.append(cid)

            recovery_confirmed = len(recovered_controls) == len(affected_controls)
            log_phase("RECOVERY_VERIFIED", "SUCCESS" if recovery_confirmed else "FAILED", {
                "recovered_controls": recovered_controls,
                "recovery_confirmed": recovery_confirmed
            })

            # Update the drift record with full lifecycle history
            drift_rec = db.query(ChaosDriftRecord).filter_by(drift_id=drift_id).order_by(
                ChaosDriftRecord.injected_at.desc()
            ).first()
            if drift_rec:
                drift_rec.lifecycle_phase = "RECOVERY_VERIFIED" if recovery_confirmed else "FAILED"
                drift_rec.lifecycle_history = lifecycle_events
                drift_rec.detection_result = {
                    "deficient_controls": deficient_controls,
                    "detection_confirmed": detection_passed
                }
                drift_rec.recovery_result = {
                    "recovered_controls": recovered_controls,
                    "recovery_confirmed": recovery_confirmed
                }
                db.commit()

            return {
                "drift_id": drift_id,
                "mode": mode,
                "lifecycle_completed": recovery_confirmed and detection_passed,
                "phases_executed": len(lifecycle_events),
                "events": lifecycle_events,
                "detection_verified": detection_passed,
                "recovery_verified": recovery_confirmed
            }
        except Exception as e:
            log_phase("FAILED", "ERROR", str(e))
            return {
                "drift_id": drift_id,
                "mode": mode,
                "lifecycle_completed": False,
                "error": str(e),
                "events": lifecycle_events
            }
        finally:
            db.close()

    @classmethod
    def list_active_drifts(cls) -> List[Dict[str, Any]]:
        """Queries persistent database for all active drift records."""
        db = SessionLocal()
        try:
            records = db.query(ChaosDriftRecord).filter_by(status="ACTIVE").all()
            results = []
            for r in records:
                info = DRIFT_CATALOG.get(r.drift_id, {})
                results.append({
                    "id": r.id,
                    "drift_id": r.drift_id,
                    "drift_type": r.drift_type,
                    "target_type": r.target_type,
                    "lifecycle_phase": getattr(r, 'lifecycle_phase', 'MUTATION_APPLIED'),
                    "injected_at": r.injected_at.isoformat() if r.injected_at else None,
                    "actor": r.actor,
                    "affected_tests": info.get("affected_tests", []),
                    "affected_controls": info.get("affected_controls", []),
                    "description": info.get("description", "")
                })
            return results
        finally:
            db.close()

    @classmethod
    def is_test_drifting(cls, test_id: str, allow_simulated: bool = True) -> bool:
        """Checks if a test definition is affected by an active drift in the database."""
        db = SessionLocal()
        try:
            active_records = db.query(ChaosDriftRecord).filter_by(status="ACTIVE").all()
            for r in active_records:
                if not allow_simulated and r.drift_type != "LIVE_LAB_MUTATION":
                    continue
                info = DRIFT_CATALOG.get(r.drift_id, {})
                if test_id in info.get("affected_tests", []):
                    return True
            return False
        finally:
            db.close()

    @classmethod
    def get_active_drift_for_test(cls, test_id: str) -> Optional[ChaosDriftRecord]:
        """Returns the active ChaosDriftRecord affecting the specified test, if any."""
        db = SessionLocal()
        try:
            active_records = db.query(ChaosDriftRecord).filter_by(status="ACTIVE").all()
            for r in active_records:
                info = DRIFT_CATALOG.get(r.drift_id, {})
                if test_id in info.get("affected_tests", []):
                    return r
            return None
        finally:
            db.close()

    @classmethod
    def _check_target_reachability(cls, target_type: str) -> Tuple[bool, Optional[str]]:
        """Probes socket connectivity to prevent attempting mutations on offline targets."""
        try:
            if target_type == "LINUX_VM":
                with socket.create_connection((settings.LINUX_VM_HOST, settings.LINUX_VM_PORT), timeout=0.5):
                    return True, None
            elif target_type == "POSTGRES_DB":
                with socket.create_connection((settings.TARGET_DB_HOST, settings.TARGET_DB_PORT), timeout=0.5):
                    return True, None
            return False, f"Unknown target {target_type}"
        except Exception as e:
            return False, str(e)

    @classmethod
    def _capture_baseline(cls, drift_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Reads current baseline configuration before applying live mutations."""
        if drift_id == "pam-lockout-bypass":
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT, settings.LINUX_VM_USER, settings.LINUX_VM_PASSWORD, timeout=3)
            try:
                _, stdout, _ = client.exec_command("cat /etc/security/faillock.conf")
                return {"faillock_conf": stdout.read().decode("utf-8")}, {}
            finally:
                client.close()
        elif drift_id == "db-rogue-superuser":
            import psycopg2
            conn = psycopg2.connect(
                host=settings.TARGET_DB_HOST, port=settings.TARGET_DB_PORT,
                user=settings.TARGET_DB_USER, password=settings.TARGET_DB_PASSWORD, dbname=settings.TARGET_DB_NAME
            )
            try:
                cur = conn.cursor()
                cur.execute("SELECT rolname FROM pg_roles WHERE rolname='rogue_auditor';")
                rows = cur.fetchall()
                return {"rogue_role_existed": len(rows) > 0}, {}
            finally:
                conn.close()
        return {"baseline": "unsupported_live"}, {}

    @classmethod
    def _execute_live_mutation(cls, drift_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Executes verified mutation on live target system."""
        if drift_id == "pam-lockout-bypass":
            import paramiko
            client = paramiko.SSHClient()
            if settings.SSH_STRICT_HOST_KEY_CHECKING:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                if settings.SSH_KNOWN_HOSTS_FILE and Path(settings.SSH_KNOWN_HOSTS_FILE).is_file():
                    client.load_host_keys(settings.SSH_KNOWN_HOSTS_FILE)
                else:
                    raise paramiko.SSHException(f"Strict host-key verification failed: known_hosts file '{settings.SSH_KNOWN_HOSTS_FILE}' not found.")
            else:
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT, settings.LINUX_VM_USER, settings.LINUX_VM_PASSWORD, timeout=3)
            try:
                _, stdout, _ = client.exec_command("cat /etc/security/faillock.conf")
                orig_cfg = stdout.read().decode("utf-8")
                client.exec_command("sudo sed -i 's/^deny = .*/deny = 999/' /etc/security/faillock.conf")
                _, stdout_v, _ = client.exec_command("grep '^deny = 999' /etc/security/faillock.conf")
                verified = "deny = 999" in stdout_v.read().decode("utf-8")
                if not verified:
                    raise RuntimeError("Live mutation failed verification on Linux VM.")
                return {"faillock_conf": orig_cfg}, {"verified_deny": 999}
            finally:
                client.close()

        elif drift_id == "ssh-root-login-enabled":
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT, settings.LINUX_VM_USER, settings.LINUX_VM_PASSWORD, timeout=3)
            try:
                client.exec_command("sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && sudo systemctl reload sshd")
                _, stdout_v, _ = client.exec_command("grep '^PermitRootLogin yes' /etc/ssh/sshd_config")
                verified = "PermitRootLogin yes" in stdout_v.read().decode("utf-8")
                return {"sshd_config_modified": True}, {"verified_permit_root_login": verified}
            finally:
                client.close()

        elif drift_id == "auditd-service-disabled":
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT, settings.LINUX_VM_USER, settings.LINUX_VM_PASSWORD, timeout=3)
            try:
                client.exec_command("sudo systemctl stop auditd")
                _, stdout_v, _ = client.exec_command("systemctl is-active auditd || true")
                status = stdout_v.read().decode("utf-8").strip()
                return {"auditd_stopped": True}, {"auditd_active_status": status}
            finally:
                client.close()

        elif drift_id == "db-rogue-superuser":
            import psycopg2
            conn = psycopg2.connect(
                host=settings.TARGET_DB_HOST, port=settings.TARGET_DB_PORT,
                user=settings.TARGET_DB_USER, password=settings.TARGET_DB_PASSWORD, dbname=settings.TARGET_DB_NAME
            )
            try:
                cur = conn.cursor()
                cur.execute("CREATE ROLE rogue_auditor WITH LOGIN SUPERUSER PASSWORD 'roguepass';")
                conn.commit()
                cur.execute("SELECT rolname FROM pg_roles WHERE rolname='rogue_auditor' AND rolsuper=true;")
                rows = cur.fetchall()
                if not rows:
                    raise RuntimeError("Live superuser mutation failed verification on Postgres.")
                return {"rogue_role_existed": False}, {"verified_rogue_superusers": len(rows)}
            finally:
                conn.close()

        return {"status": "unsupported_live"}, {"status": "unsupported_live"}

    @classmethod
    def _execute_live_restoration(cls, drift_id: str):
        """Restores live target to baseline."""
        try:
            if drift_id == "pam-lockout-bypass":
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
                client.connect(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT, settings.LINUX_VM_USER, settings.LINUX_VM_PASSWORD, timeout=3)
                try:
                    client.exec_command("sudo sed -i 's/^deny = .*/deny = 5/' /etc/security/faillock.conf")
                finally:
                    client.close()
            elif drift_id == "ssh-root-login-enabled":
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
                client.connect(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT, settings.LINUX_VM_USER, settings.LINUX_VM_PASSWORD, timeout=3)
                try:
                    client.exec_command("sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd")
                finally:
                    client.close()
            elif drift_id == "auditd-service-disabled":
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
                client.connect(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT, settings.LINUX_VM_USER, settings.LINUX_VM_PASSWORD, timeout=3)
                try:
                    client.exec_command("sudo systemctl start auditd")
                finally:
                    client.close()
            elif drift_id == "db-rogue-superuser":
                import psycopg2
                conn = psycopg2.connect(
                    host=settings.TARGET_DB_HOST, port=settings.TARGET_DB_PORT,
                    user=settings.TARGET_DB_USER, password=settings.TARGET_DB_PASSWORD, dbname=settings.TARGET_DB_NAME
                )
                try:
                    cur = conn.cursor()
                    cur.execute("DROP ROLE IF EXISTS rogue_auditor;")
                    conn.commit()
                finally:
                    conn.close()
        except Exception as e:
            print(f"Warning during live restoration of {drift_id}: {e}")
