import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from unittest.mock import patch

from app.main import app, orchestrator
from app.config import settings
from app.database import SessionLocal
from app.models.assessment import AssessmentRun
from app.models.base import utc_now

TEST_AUDITOR_TOKEN = "test-auditor-token-secret-xyz"
TEST_ENGINEER_TOKEN = "test-engineer-token-secret-123"

@pytest.fixture(autouse=True)
def configure_test_auth():
    """Sets explicit deterministic tokens for test execution."""
    orig_admin = settings.CAC_ADMIN_TOKEN
    orig_eng = settings.CAC_ENGINEER_TOKEN
    orig_aud = settings.CAC_AUDITOR_TOKEN
    orig_auth = settings.AUTH_ENABLED
    orig_bypass = settings.DEV_AUTH_BYPASS

    settings.CAC_ADMIN_TOKEN = "test-admin-token-secret-456"
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

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    yield session
    session.close()


def test_async_run_all_returns_202_and_task_id(client: TestClient):
    """
    POST /api/v1/orchestrator/run-all without sync=true must return HTTP 202 Accepted,
    a valid UUID task_id, and a poll URL without blocking the request thread.
    """
    eng_headers = {"Authorization": f"Bearer {TEST_ENGINEER_TOKEN}"}
    r = client.post("/api/v1/orchestrator/run-all?allow_simulation=true", headers=eng_headers)
    
    assert r.status_code == 202
    data = r.json()
    assert "task_id" in data
    assert len(data["task_id"]) == 36
    assert data["status"] in ("QUEUED", "RUNNING", "COMPLETED")
    assert f"/api/v1/orchestrator/status/{data['task_id']}" in data["poll_url"]


def test_status_endpoint_returns_completed_task(client: TestClient):
    """
    Polling GET /api/v1/orchestrator/status/{task_id} returns 200 and the completed
    task summary once the background worker finishes.
    """
    eng_headers = {"Authorization": f"Bearer {TEST_ENGINEER_TOKEN}"}
    auditor_headers = {"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"}

    # 1. Dispatch async task
    r_run = client.post("/api/v1/orchestrator/run-all?allow_simulation=true", headers=eng_headers)
    assert r_run.status_code == 202
    task_id = r_run.json()["task_id"]

    # 2. Query status endpoint (Starlette TestClient executes BackgroundTasks before request finishes)
    r_status = client.get(f"/api/v1/orchestrator/status/{task_id}", headers=auditor_headers)
    assert r_status.status_code == 200
    status_data = r_status.json()

    assert status_data["task_id"] == task_id
    assert status_data["status"] == "COMPLETED"
    assert status_data["duration_ms"] is not None
    assert status_data["assessment_id"] is not None
    assert "result" in status_data
    assert status_data["result"]["total_tests"] > 0
    assert status_data["error"] is None


def test_sync_mode_returns_200_ok(client: TestClient):
    """
    POST /api/v1/orchestrator/run-all?sync=true returns HTTP 200 OK directly with execution dictionary.
    """
    eng_headers = {"Authorization": f"Bearer {TEST_ENGINEER_TOKEN}"}
    r = client.post("/api/v1/orchestrator/run-all?allow_simulation=true&sync=true", headers=eng_headers)
    
    assert r.status_code == 200
    data = r.json()
    assert "assessment_id" in data
    assert "total_tests" in data
    assert "results" in data


def test_status_endpoint_404_for_unknown_task(client: TestClient):
    """
    GET /api/v1/orchestrator/status/{task_id} returns 404 if task ID does not exist in memory or DB.
    """
    auditor_headers = {"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"}
    r = client.get("/api/v1/orchestrator/status/non-existent-task-id-12345", headers=auditor_headers)
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


def test_status_endpoint_historical_db_fallback(client: TestClient, db: Session):
    """
    If a task is not in the in-memory cache, the status endpoint falls back to querying
    the persistent AssessmentRun database table.
    """
    auditor_headers = {"Authorization": f"Bearer {TEST_AUDITOR_TOKEN}"}
    now = utc_now()
    historical_run = AssessmentRun(
        run_type="HISTORICAL_ARCHIVE",
        started_at=now,
        completed_at=now,
        duration_ms=45,
        total_tests=5,
        passed_count=4,
        failed_count=1,
        error_count=0,
        execution_summary={"results": [{"test_id": "TEST-ARCHIVE-1", "result_code": 1}]}
    )
    db.add(historical_run)
    db.commit()

    # Query status endpoint for historical run ID
    r = client.get(f"/api/v1/orchestrator/status/{historical_run.id}", headers=auditor_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["task_id"] == historical_run.id
    assert data["status"] == "COMPLETED"
    assert data["run_type"] == "HISTORICAL_ARCHIVE"
    assert data["duration_ms"] == 45
    assert data["result"]["total_tests"] == 5


def test_status_endpoint_requires_auditor_authentication(client: TestClient):
    """
    GET /api/v1/orchestrator/status/{task_id} rejects unauthenticated requests with 401.
    """
    r = client.get("/api/v1/orchestrator/status/some-task-id")
    assert r.status_code == 401


def test_task_memory_pruning():
    """
    Verifies that create_task prunes oldest completed tasks when task dictionary exceeds 500 items.
    """
    # Populate dummy completed tasks
    with orchestrator._task_lock:
        orchestrator._tasks.clear()
        for i in range(505):
            tid = f"task-dummy-{i}"
            orchestrator._tasks[tid] = {
                "task_id": tid,
                "status": "COMPLETED",
                "created_at": "2026-10-24T00:00:00Z"
            }

    # Creating a new task should trigger pruning
    res = orchestrator.create_task(allow_simulation=True)
    assert "task_id" in res
    with orchestrator._task_lock:
        assert len(orchestrator._tasks) <= 410


def test_background_assessment_captures_exceptions():
    """
    Verifies that if execute_all_tests raises an unexpected exception,
    run_background_assessment catches it and marks status as FAILED with error detail.
    """
    task = orchestrator.create_task(allow_simulation=True)
    tid = task["task_id"]

    with patch.object(orchestrator, "execute_all_tests", side_effect=RuntimeError("Simulated internal runner crash")):
        orchestrator.run_background_assessment(tid, allow_simulation=True)

    status_data = orchestrator.get_task_status(None, tid)
    assert status_data is not None
    assert status_data["status"] == "FAILED"
    assert "Simulated internal runner crash" in status_data["error"]
