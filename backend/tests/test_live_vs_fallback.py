import pytest
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.evidence import EvidenceRecord
from app.models.score import EWCESScore
from app.models.chaos import ChaosDriftRecord
from app.engine.runner.ssh_runner import SSHRunner
from app.engine.runner.db_runner import DBRunner
from app.engine.orchestrator import TestOrchestrator
from app.engine.scoring.classifier import STATE_UNKNOWN, EWCESClassifier

@pytest.fixture(scope="function")
def db():
    session = SessionLocal()
    # Ensure no residual active chaos drifts interfere with isolation
    session.query(ChaosDriftRecord).filter_by(status="ACTIVE").update({"status": "RESTORED"})
    session.query(EvidenceRecord).filter(
        EvidenceRecord.test_id.in_(["TEST-VM-PAM-LOCKOUT-T1", "TEST-VM-PAM-LOCKOUT-T2"])
    ).delete()
    session.commit()
    yield session
    session.close()

def test_ssh_runner_offline_returns_connection_error():
    """
    Verifies that when a live SSH target is unreachable and allow_simulation=False,
    the runner reports CONNECTION_ERROR with result_code=0, NEVER claiming PASS.
    """
    runner = SSHRunner(host="192.0.2.1", port=9922) # RFC 5737 TEST-NET-1 unroutable IP
    result = runner.execute(
        test_id="TEST-VM-PAM-LOCKOUT-T1",
        tier=1,
        test_spec={"command": "grep pam_faillock /etc/pam.d/common-auth"},
        allow_simulation=False
    )
    assert result.result_code == 0
    assert result.execution_status == "CONNECTION_ERROR"
    assert result.evidence_provenance == "LIVE_TARGET"
    assert "unreachable" in result.error_message.lower()

def test_db_runner_offline_returns_connection_error():
    """
    Verifies that when a live PostgreSQL target is unreachable and allow_simulation=False,
    the runner reports CONNECTION_ERROR with result_code=0, NEVER claiming PASS.
    """
    runner = DBRunner(host="192.0.2.1", port=9933)
    result = runner.execute(
        test_id="TEST-DB-LEAST-PRIVILEGE-T1",
        tier=1,
        test_spec={"sql": "SELECT 1;"},
        allow_simulation=False
    )
    assert result.result_code == 0
    assert result.execution_status in ("CONNECTION_ERROR", "DRIVER_UNAVAILABLE")
    assert result.evidence_provenance == "LIVE_TARGET"

def test_orchestrator_preserves_provenance_and_marks_offline_as_unknown(db: Session):
    """
    Verifies that running with allow_simulation=False against an offline target
    persists evidence with execution_status=CONNECTION_ERROR and sets EW-CES to UNKNOWN.
    """
    orchestrator = TestOrchestrator()
    # Point SSH runner to offline host
    orchestrator.ssh_runner = SSHRunner(host="192.0.2.1", port=9922)

    res = orchestrator.execute_test(
        db=db,
        test_id="TEST-VM-PAM-LOCKOUT-T1",
        allow_simulation=False
    )

    assert res["execution_status"] == "CONNECTION_ERROR"
    assert res["provenance"] == "LIVE_TARGET"
    assert res["result_code"] == 0
    # Because config probe errored out, control state must be UNKNOWN
    assert res["new_state"] == STATE_UNKNOWN

def test_offline_runners_never_synthesize_pass_even_when_allow_simulation_is_true():
    """
    Critical integrity test (P0.1 audit requirement):
    Asserts that offline targets never fabricate a passing result (result_code=1)
    even if allow_simulation=True was provided.
    """
    # 1. SSH Runner
    ssh_runner = SSHRunner(host="192.0.2.1", port=9922)
    res_ssh = ssh_runner.execute(
        test_id="TEST-VM-PAM-LOCKOUT-T1",
        tier=1,
        test_spec={"command": "grep pam_faillock /etc/pam.d/common-auth"},
        allow_simulation=True
    )
    assert res_ssh.result_code == 0
    assert res_ssh.execution_status == "CONNECTION_ERROR"
    assert res_ssh.result_code != 1

    # 2. DB Runner
    db_runner = DBRunner(host="192.0.2.1", port=9933)
    res_db = db_runner.execute(
        test_id="TEST-DB-LEAST-PRIVILEGE-T1",
        tier=1,
        test_spec={"sql": "SELECT 1;"},
        allow_simulation=True
    )
    assert res_db.result_code == 0
    assert res_db.execution_status in ("CONNECTION_ERROR", "DRIVER_UNAVAILABLE")
    assert res_db.result_code != 1

def test_orchestrator_offline_target_marks_error_and_unknown_with_allow_simulation_true(db: Session):
    """
    Asserts that orchestrator evaluates control to UNKNOWN when target is offline,
    even if allow_simulation=True was passed.
    """
    orchestrator = TestOrchestrator()
    orchestrator.ssh_runner = SSHRunner(host="192.0.2.1", port=9922)

    res = orchestrator.execute_test(
        db=db,
        test_id="TEST-VM-PAM-LOCKOUT-T1",
        allow_simulation=True
    )

    assert res["result_code"] == 0
    assert res["execution_status"] == "CONNECTION_ERROR"
    assert res["new_state"] == STATE_UNKNOWN

def test_live_lab_integration_safely_skipped_when_target_offline():
    """
    Integration probe: Verifies that if the local lab environment is offline,
    the test suite does not fabricate a live pass or fail CI, but skips with informative notice.
    """
    from app.services.asset_service import AssetService
    from app.config import settings

    vm_online = AssetService.probe_socket(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT)
    if not vm_online:
        pytest.skip(
            f"Lab VM target at {settings.LINUX_VM_HOST}:{settings.LINUX_VM_PORT} is currently offline. "
            f"Agentless runner safe fallback verified. Live hardware test skipped without fabricated pass."
        )

    # If VM is online, perform actual live execution
    runner = SSHRunner()
    res = runner.execute(
        test_id="TEST-VM-PAM-LOCKOUT-T1",
        tier=1,
        test_spec={"command": "grep pam_faillock /etc/pam.d/common-auth"},
        allow_simulation=False
    )
    assert res.evidence_provenance == "LIVE_TARGET"
