import time
import uuid
import threading
import logging
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

from app.models.test_definition import TestDefinition
from app.models.mapping import PolicyMapping
from app.models.assessment import AssessmentRun
from app.models.base import utc_now
from app.engine.runner.ssh_runner import SSHRunner
from app.engine.runner.db_runner import DBRunner
from app.engine.runner.base import TestResult
from app.engine.ledger.vault import EvidenceVault
from app.engine.scoring.classifier import EWCESClassifier
from app.chaos.mutations import ChaosInjector

class TestOrchestrator:
    """
    Coordinates agentless test execution across hybrid lab targets,
    commits cryptographic evidence to the vault, and triggers EW-CES re-scoring.
    Supports asynchronous background execution and status polling.
    """
    __test__ = False # Prevent pytest from collecting this class as a test suite

    def __init__(self):
        self.ssh_runner = SSHRunner()
        self.db_runner = DBRunner()
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._task_lock = threading.Lock()

    def execute_test(self, db: Session, test_id: str, allow_simulation: bool = True) -> Dict[str, Any]:
        """
        Runs a single test definition, commits evidence, and returns summary.
        allow_simulation: If True, uses deterministic simulation when target VM/containers are offline.
        """
        test_def = db.query(TestDefinition).filter_by(test_id=test_id).first()
        if not test_def:
            raise ValueError(f"TestDefinition '{test_id}' not found.")

        # Check if active chaos drift is injected for this test
        active_drift = ChaosInjector.get_active_drift_for_test(test_id)
        if active_drift and active_drift.drift_type == "SIMULATED":
            result = TestResult(
                test_id=test_id,
                result_code=-1, # Explicit Failure caused by Simulated Drift
                execution_status="FAILURE",
                evidence_provenance="SIMULATED_LAB",
                tier=test_def.tier,
                target_type=test_def.target_type,
                duration_ms=12,
                raw_telemetry={
                    "status": "FAIL",
                    "failure_reason": f"Simulated chaos compliance drift '{active_drift.drift_id}' active in database. Security assertion violated.",
                    "active_mutation": True,
                    "drift_id": active_drift.drift_id
                },
                collected_at=utc_now()
            )
        else:
            # If drift is LIVE_LAB_MUTATION or no drift, probe the target directly.
            # For live mutations, the target has been mutated and will produce an authentic live failure.
            if test_def.target_type == "LINUX_VM":
                result = self.ssh_runner.execute(
                    test_id=test_def.test_id, tier=test_def.tier,
                    test_spec=test_def.test_spec, allow_simulation=allow_simulation
                )
            elif test_def.target_type == "POSTGRES_DB":
                result = self.db_runner.execute(
                    test_id=test_def.test_id, tier=test_def.tier,
                    test_spec=test_def.test_spec, allow_simulation=allow_simulation
                )
            else:
                raise ValueError(f"Unsupported target type: {test_def.target_type}")

        # 2. Commit evidence to ledger
        evidence_record = EvidenceVault.commit_evidence(db, result)

        # 3. Find parent control and re-score
        mapping = db.query(PolicyMapping).filter_by(id=test_def.mapping_id).first()
        score_record = None
        if mapping:
            score_record = EWCESClassifier.evaluate_control(db, mapping.control_id)

        return {
            "test_id": test_id,
            "target": test_def.target_type,
            "tier": test_def.tier,
            "result_code": result.result_code,
            "execution_status": result.execution_status,
            "provenance": result.evidence_provenance,
            "evidence_id": evidence_record.id,
            "payload_sha256": evidence_record.payload_sha256,
            "control_id": mapping.control_id if mapping else None,
            "new_state": score_record.state if score_record else None
        }

    def execute_all_tests(self, db: Session, allow_simulation: bool = True, run_type: str = "MANUAL_ADHOC") -> Dict[str, Any]:
        """
        Runs all configured Compliance-as-Code tests across the testbed,
        creates an AssessmentRun record, and returns summary metrics.
        """
        start_time = time.time()
        start_dt = utc_now()
        tests = db.query(TestDefinition).all()
        results = []
        passed = 0
        failed = 0
        errors = 0

        for t in tests:
            res = self.execute_test(db, t.test_id, allow_simulation=allow_simulation)
            results.append(res)
            if res["result_code"] == 1:
                passed += 1
            elif res["result_code"] == -1:
                failed += 1
            else:
                errors += 1

        duration_ms = int((time.time() - start_time) * 1000)

        # Record historical AssessmentRun
        assessment = AssessmentRun(
            run_type=run_type,
            started_at=start_dt,
            completed_at=utc_now(),
            duration_ms=duration_ms,
            total_tests=len(tests),
            passed_count=passed,
            failed_count=failed,
            error_count=errors,
            execution_summary={"results": results}
        )
        db.add(assessment)
        db.commit()

        return {
            "assessment_id": assessment.id,
            "duration_ms": duration_ms,
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "results": results
        }

    def create_task(self, allow_simulation: bool = True, run_type: str = "MANUAL_ADHOC") -> Dict[str, Any]:
        """
        Creates and registers a new asynchronous assessment task in QUEUED state.
        Prunes old completed/failed tasks if in-memory cache exceeds 500 items.
        """
        task_id = str(uuid.uuid4())
        now_iso = utc_now().isoformat()
        task_record = {
            "task_id": task_id,
            "status": "QUEUED",
            "run_type": run_type,
            "allow_simulation": allow_simulation,
            "created_at": now_iso,
            "started_at": None,
            "completed_at": None,
            "duration_ms": None,
            "assessment_id": None,
            "result": None,
            "error": None
        }

        with self._task_lock:
            if len(self._tasks) > 500:
                completed_keys = [
                    k for k, v in self._tasks.items()
                    if v.get("status") in ("COMPLETED", "FAILED")
                ]
                for k in completed_keys[:100]:
                    self._tasks.pop(k, None)

            self._tasks[task_id] = task_record

        return {
            "task_id": task_id,
            "status": "QUEUED",
            "message": "Assessment sweep queued for background execution.",
            "created_at": now_iso,
            "poll_url": f"/api/v1/orchestrator/status/{task_id}"
        }

    def run_background_assessment(
        self,
        task_id: str,
        allow_simulation: bool = True,
        run_type: str = "MANUAL_ADHOC"
    ) -> None:
        """
        Executes the assessment suite in a background worker with an isolated database session.
        Transitions task status from QUEUED -> RUNNING -> COMPLETED or FAILED.
        """
        from app.database import SessionLocal

        with self._task_lock:
            if task_id in self._tasks:
                self._tasks[task_id]["status"] = "RUNNING"
                self._tasks[task_id]["started_at"] = utc_now().isoformat()

        db = SessionLocal()
        try:
            result = self.execute_all_tests(db, allow_simulation=allow_simulation, run_type=run_type)
            with self._task_lock:
                if task_id in self._tasks:
                    self._tasks[task_id]["status"] = "COMPLETED"
                    self._tasks[task_id]["completed_at"] = utc_now().isoformat()
                    self._tasks[task_id]["duration_ms"] = result.get("duration_ms", 0)
                    self._tasks[task_id]["assessment_id"] = result.get("assessment_id")
                    self._tasks[task_id]["result"] = result
        except Exception as exc:
            logger.exception("Background assessment task %s failed with exception: %s", task_id, exc)
            with self._task_lock:
                if task_id in self._tasks:
                    self._tasks[task_id]["status"] = "FAILED"
                    self._tasks[task_id]["completed_at"] = utc_now().isoformat()
                    self._tasks[task_id]["error"] = str(exc)
        finally:
            db.close()

    def get_task_status(self, db: Optional[Session], task_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the execution status and results of a task.
        Checks in-memory task cache first; if not found, checks the database AssessmentRun table.
        """
        with self._task_lock:
            if task_id in self._tasks:
                return dict(self._tasks[task_id])

        if db is not None:
            assessment = db.query(AssessmentRun).filter_by(id=task_id).first()
            if assessment:
                results_list = []
                if assessment.execution_summary and isinstance(assessment.execution_summary, dict):
                    results_list = assessment.execution_summary.get("results", [])

                return {
                    "task_id": assessment.id,
                    "status": "COMPLETED",
                    "run_type": assessment.run_type,
                    "allow_simulation": True,
                    "created_at": assessment.started_at.isoformat() if assessment.started_at else None,
                    "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
                    "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
                    "duration_ms": assessment.duration_ms,
                    "assessment_id": assessment.id,
                    "result": {
                        "assessment_id": assessment.id,
                        "duration_ms": assessment.duration_ms,
                        "total_tests": assessment.total_tests,
                        "passed": assessment.passed_count,
                        "failed": assessment.failed_count,
                        "errors": assessment.error_count,
                        "results": results_list
                    },
                    "error": None
                }

        return None

