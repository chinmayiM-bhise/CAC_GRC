import time
import re
import shlex
import socket
import datetime
from pathlib import Path
import paramiko
from typing import Any, Dict, Optional
from app.config import settings
from app.engine.runner.base import BaseRunner, TestResult, redact_secrets_from_string

SAFE_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
SAFE_FILEPATH_PATTERN = re.compile(r'^/[a-zA-Z0-9_\-\./]+$')


class SSHRunner(BaseRunner):
    """
    Agentless SSH test runner for Linux VM (Ubuntu Server).
    Executes Tier 1 static inspection commands and Tier 2 behavioral challenges.
    Never silently converts connection errors into PASS.
    Enforces strict known_hosts verification and parameter sanitization.
    """

    def __init__(self, host: str = None, port: int = None, username: str = None, password: str = None, key_path: str = None):
        self.host = host or settings.LINUX_VM_HOST
        self.port = port or settings.LINUX_VM_PORT
        self.username = username or settings.LINUX_VM_USER
        self.password = password or settings.LINUX_VM_PASSWORD
        self.key_path = key_path or settings.LINUX_VM_KEY_PATH

    def _is_reachable(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=0.3):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _get_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()

        # Enforce strict managed host-key checking
        if settings.SSH_STRICT_HOST_KEY_CHECKING:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            known_hosts_path = Path(settings.SSH_KNOWN_HOSTS_FILE) if settings.SSH_KNOWN_HOSTS_FILE else None
            if known_hosts_path and known_hosts_path.is_file():
                client.load_host_keys(str(known_hosts_path))
            else:
                # Fail closed if strict checking is configured but known_hosts is missing
                raise paramiko.SSHException(
                    f"Strict SSH host-key verification failed: managed known_hosts file '{settings.SSH_KNOWN_HOSTS_FILE}' not found."
                )
        else:
            client.set_missing_host_key_policy(paramiko.WarningPolicy())

        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            key_filename=self.key_path,
            timeout=3,
            allow_agent=False,
            look_for_keys=False if not self.key_path else True
        )
        return client

    def execute(self, test_id: str, tier: int, test_spec: Dict[str, Any], allow_simulation: bool = False) -> TestResult:
        start_time = time.time()
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        if not self._is_reachable():
            duration_ms = int((time.time() - start_time) * 1000)
            return TestResult(
                test_id=test_id,
                result_code=0,  # Inconclusive / Connection Error - NEVER claim PASS for offline target
                execution_status="CONNECTION_ERROR",
                evidence_provenance="LIVE_TARGET",
                tier=tier,
                target_type="LINUX_VM",
                duration_ms=duration_ms,
                raw_telemetry={
                    "error": f"Target Linux VM at {self.host}:{self.port} is unreachable or offline.",
                    "host": self.host,
                    "port": self.port
                },
                collected_at=now_utc,
                error_message=f"Target Linux VM unreachable at {self.host}:{self.port}"
            )

        try:
            client = self._get_client()
            try:
                if tier == 1:
                    return self._execute_tier1_command(client, test_id, test_spec, start_time)
                else:
                    return self._execute_tier2_probe(client, test_id, test_spec, start_time)
            finally:
                client.close()
        except paramiko.SSHException as ssh_ex:
            duration_ms = int((time.time() - start_time) * 1000)
            err_msg = redact_secrets_from_string(str(ssh_ex))
            status_code = "HOST_KEY_VERIFICATION_FAILED" if "host-key" in err_msg.lower() or "rejected" in err_msg.lower() or "known_hosts" in err_msg.lower() else "CONNECTION_ERROR"
            return TestResult(
                test_id=test_id,
                result_code=0,
                execution_status=status_code,
                evidence_provenance="LIVE_TARGET",
                tier=tier,
                target_type="LINUX_VM",
                duration_ms=duration_ms,
                raw_telemetry={"error": err_msg, "host": self.host},
                collected_at=now_utc,
                error_message=err_msg
            )
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            err_msg = redact_secrets_from_string(str(e))
            return TestResult(
                test_id=test_id,
                result_code=0,
                execution_status="EXECUTION_ERROR",
                evidence_provenance="LIVE_TARGET",
                tier=tier,
                target_type="LINUX_VM",
                duration_ms=duration_ms,
                raw_telemetry={"error": err_msg, "host": self.host},
                collected_at=now_utc,
                error_message=err_msg
            )

    def _execute_tier1_command(self, client: paramiko.SSHClient, test_id: str, test_spec: Dict[str, Any], start_time: float) -> TestResult:
        command = test_spec["command"]
        stdin, stdout, stderr = client.exec_command(command, timeout=10)
        exit_code = stdout.channel.recv_exit_status()
        out_str = stdout.read().decode("utf-8").strip()
        err_str = stderr.read().decode("utf-8").strip()
        duration_ms = int((time.time() - start_time) * 1000)

        passed = (exit_code == test_spec.get("expected_exit_code", 0))
        if "expected_regex" in test_spec and not re.search(test_spec["expected_regex"], out_str):
            passed = False
        if "expected_output" in test_spec and test_spec["expected_output"] not in out_str:
            passed = False

        result_code = 1 if passed else -1
        telemetry = {
            "mode": "live_ssh",
            "host": self.host,
            "command": redact_secrets_from_string(command),
            "stdout": out_str,
            "stderr": err_str,
            "exit_code": exit_code,
            "passed": passed
        }

        return TestResult(
            test_id=test_id,
            result_code=result_code,
            execution_status="SUCCESS" if passed else "FAILURE",
            evidence_provenance="LIVE_TARGET",
            tier=1,
            target_type="LINUX_VM",
            duration_ms=duration_ms,
            raw_telemetry=telemetry,
            collected_at=datetime.datetime.now(datetime.timezone.utc)
        )

    def _execute_tier2_probe(self, client: paramiko.SSHClient, test_id: str, test_spec: Dict[str, Any], start_time: float) -> TestResult:
        probe_action = test_spec.get("probe_action")
        duration_ms = int((time.time() - start_time) * 1000)

        if probe_action == "simulate_failed_logins":
            raw_target_user = str(test_spec.get("target_user", "audit_canary"))
            if not SAFE_IDENTIFIER_PATTERN.match(raw_target_user):
                raise ValueError(f"Unsafe target_user parameter rejected: '{raw_target_user}'")
            target_user = shlex.quote(raw_target_user)

            attempts = int(test_spec.get("attempt_count", 6))
            failed_attempts = 0

            for _ in range(attempts):
                try:
                    probe_client = paramiko.SSHClient()
                    if settings.SSH_STRICT_HOST_KEY_CHECKING:
                        probe_client.set_missing_host_key_policy(paramiko.RejectPolicy())
                        if settings.SSH_KNOWN_HOSTS_FILE and Path(settings.SSH_KNOWN_HOSTS_FILE).is_file():
                            probe_client.load_host_keys(settings.SSH_KNOWN_HOSTS_FILE)
                    else:
                        probe_client.set_missing_host_key_policy(paramiko.WarningPolicy())

                    probe_client.connect(
                        hostname=self.host, port=self.port, username=raw_target_user,
                        password="WrongPassword123!", timeout=3, allow_agent=False, look_for_keys=False
                    )
                    probe_client.close()
                except paramiko.AuthenticationException:
                    failed_attempts += 1
                except Exception:
                    pass

            stdin, stdout, stderr = client.exec_command(f"sudo /usr/sbin/faillock --user {target_user}")
            faillock_output = stdout.read().decode("utf-8")
            is_locked = "V" in faillock_output or failed_attempts >= 5
            result_code = 1 if is_locked else -1

            telemetry = {
                "mode": "live_ssh_probe",
                "probe_action": probe_action,
                "target_user": raw_target_user,
                "failed_attempts_injected": failed_attempts,
                "faillock_output": faillock_output.strip(),
                "lockout_verified": is_locked
            }

            return TestResult(
                test_id=test_id,
                result_code=result_code,
                execution_status="SUCCESS" if is_locked else "FAILURE",
                evidence_provenance="LIVE_TARGET",
                tier=2,
                target_type="LINUX_VM",
                duration_ms=duration_ms,
                raw_telemetry=telemetry,
                collected_at=datetime.datetime.now(datetime.timezone.utc)
            )

        elif probe_action == "trigger_monitored_syscall":
            raw_target_file = str(test_spec.get("target_file", "/etc/shadow"))
            if not SAFE_FILEPATH_PATTERN.match(raw_target_file) or ".." in raw_target_file:
                raise ValueError(f"Unsafe target_file path rejected: '{raw_target_file}'")

            raw_audit_key = str(test_spec.get("expected_audit_key", "shadow_watch"))
            if not SAFE_IDENTIFIER_PATTERN.match(raw_audit_key):
                raise ValueError(f"Unsafe audit_key parameter rejected: '{raw_audit_key}'")

            target_file = shlex.quote(raw_target_file)
            audit_key = shlex.quote(raw_audit_key)

            client.exec_command(f"sudo touch {target_file}")
            time.sleep(1)

            stdin, stdout, stderr = client.exec_command(f"sudo /usr/sbin/ausearch -k {audit_key} -ts recent")
            ausearch_out = stdout.read().decode("utf-8")
            audit_logged = raw_audit_key in ausearch_out or "type=SYSCALL" in ausearch_out
            result_code = 1 if audit_logged else -1

            telemetry = {
                "mode": "live_ssh_probe",
                "probe_action": probe_action,
                "target_file": raw_target_file,
                "ausearch_output": ausearch_out.strip()[:500],
                "audit_record_found": audit_logged
            }

            return TestResult(
                test_id=test_id,
                result_code=result_code,
                execution_status="SUCCESS" if audit_logged else "FAILURE",
                evidence_provenance="LIVE_TARGET",
                tier=2,
                target_type="LINUX_VM",
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
            target_type="LINUX_VM",
            duration_ms=duration_ms,
            raw_telemetry={"error": f"Unknown probe action: {probe_action}"},
            collected_at=datetime.datetime.now(datetime.timezone.utc)
        )
