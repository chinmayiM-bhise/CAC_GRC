import time
import socket
import datetime
from typing import Any, Dict, Optional
from app.config import settings
from app.engine.runner.base import BaseRunner, TestResult, redact_secrets_from_string

try:
    import psycopg2
except ImportError:
    psycopg2 = None

class DBRunner(BaseRunner):
    """
    Agentless database test runner for Target PostgreSQL.
    Audits roles, least privilege, and TLS connection security.
    Never silently converts connection errors into PASS.
    """

    def __init__(self, host: str = None, port: int = None, user: str = None, password: str = None, dbname: str = None):
        self.host = host or settings.TARGET_DB_HOST
        self.port = port or settings.TARGET_DB_PORT
        self.user = user or settings.TARGET_DB_USER
        self.password = password or settings.TARGET_DB_PASSWORD
        self.dbname = dbname or settings.TARGET_DB_NAME

    def _is_reachable(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=0.3):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def execute(self, test_id: str, tier: int, test_spec: Dict[str, Any], allow_simulation: bool = False) -> TestResult:
        start_time = time.time()
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        if not psycopg2:
            return TestResult(
                test_id=test_id,
                result_code=0,
                execution_status="DRIVER_UNAVAILABLE",
                evidence_provenance="LIVE_TARGET",
                tier=tier,
                target_type="POSTGRES_DB",
                duration_ms=5,
                raw_telemetry={"error": "psycopg2 driver not installed in environment"},
                collected_at=now_utc,
                error_message="psycopg2 driver not installed"
            )

        if not self._is_reachable():
            duration_ms = int((time.time() - start_time) * 1000)
            return TestResult(
                test_id=test_id,
                result_code=0,  # Inconclusive / Connection Error - NEVER claim PASS for offline target
                execution_status="CONNECTION_ERROR",
                evidence_provenance="LIVE_TARGET",
                tier=tier,
                target_type="POSTGRES_DB",
                duration_ms=duration_ms,
                raw_telemetry={"error": f"Target PostgreSQL DB at {self.host}:{self.port} is unreachable or offline."},
                collected_at=now_utc,
                error_message=f"PostgreSQL target unreachable at {self.host}:{self.port}"
            )

        try:
            if tier == 1:
                return self._execute_tier1_query(test_id, test_spec, start_time)
            else:
                return self._execute_tier2_probe(test_id, test_spec, start_time)
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return TestResult(
                test_id=test_id,
                result_code=0,
                execution_status="EXECUTION_ERROR",
                evidence_provenance="LIVE_TARGET",
                tier=tier,
                target_type="POSTGRES_DB",
                duration_ms=duration_ms,
                raw_telemetry={"error": str(e)},
                collected_at=now_utc,
                error_message=str(e)
            )

    def _execute_tier1_query(self, test_id: str, test_spec: Dict[str, Any], start_time: float) -> TestResult:
        conn = psycopg2.connect(
            host=self.host, port=self.port, user=self.user,
            password=self.password, dbname=self.dbname, connect_timeout=3
        )
        try:
            cur = conn.cursor()
            query = test_spec["query"]
            cur.execute(query)
            rows = cur.fetchall()
            duration_ms = int((time.time() - start_time) * 1000)

            passed = True
            if "expected_row_count" in test_spec:
                passed = (len(rows) == test_spec["expected_row_count"])
            if "expected_result" in test_spec:
                passed = (len(rows) > 0 and str(rows[0][0]).lower() == test_spec["expected_result"].lower())

            result_code = 1 if passed else -1
            telemetry = {
                "mode": "live_sql",
                "query": query,
                "row_count": len(rows),
                "rows_sample": [str(r) for r in rows[:5]],
                "passed": passed
            }

            return TestResult(
                test_id=test_id,
                result_code=result_code,
                execution_status="SUCCESS" if passed else "FAILURE",
                evidence_provenance="LIVE_TARGET",
                tier=1,
                target_type="POSTGRES_DB",
                duration_ms=duration_ms,
                raw_telemetry=telemetry,
                collected_at=datetime.datetime.now(datetime.timezone.utc)
            )
        finally:
            conn.close()

    def _execute_tier2_probe(self, test_id: str, test_spec: Dict[str, Any], start_time: float) -> TestResult:
        probe_action = test_spec.get("probe_action")
        duration_ms = int((time.time() - start_time) * 1000)

        if probe_action == "attempt_unencrypted_handshake":
            rejection_occurred = False
            try:
                conn = psycopg2.connect(
                    host=self.host, port=self.port, user=self.user,
                    password=self.password, dbname=self.dbname, sslmode="disable", connect_timeout=3
                )
                conn.close()
                rejection_occurred = False # Plaintext connection allowed -> control failed!
            except psycopg2.OperationalError as ex:
                if "no pg_hba.conf entry" in str(ex) or "SSL" in str(ex) or "encryption" in str(ex):
                    rejection_occurred = True

            passed = (rejection_occurred == test_spec.get("expected_rejection", True))
            result_code = 1 if passed else -1

            telemetry = {
                "mode": "live_sql_probe",
                "probe_action": probe_action,
                "unencrypted_rejection_observed": rejection_occurred,
                "passed": passed
            }

            return TestResult(
                test_id=test_id,
                result_code=result_code,
                execution_status="SUCCESS" if passed else "FAILURE",
                evidence_provenance="LIVE_TARGET",
                tier=2,
                target_type="POSTGRES_DB",
                duration_ms=duration_ms,
                raw_telemetry=telemetry,
                collected_at=datetime.datetime.now(datetime.timezone.utc)
            )

        return TestResult(
            test_id=test_id,
            result_code=0,
            execution_status="INCONCLUSIVE",
            evidence_provenance="LIVE_TARGET",
            tier=2,
            target_type="POSTGRES_DB",
            duration_ms=duration_ms,
            raw_telemetry={"error": f"Unknown DB probe: {probe_action}"},
            collected_at=datetime.datetime.now(datetime.timezone.utc)
        )
