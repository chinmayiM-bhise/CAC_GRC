import os
import shutil
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from experiments.benchmark_ew_ces_vs_binary import (
    execute_benchmark,
    SCENARIOS,
    BenchmarkScenario,
    TraditionalBinaryScorer
)
from app.engine.scoring.classifier import STATE_VERIFIED_EFFECTIVE, STATE_UNKNOWN

@pytest.fixture(scope="module")
def db(tmp_path_factory):
    """
    Provides an isolated clone of the database for benchmark testing,
    preventing benchmark evidence mutations from altering cac_grc.db.
    """
    temp_dir = tmp_path_factory.mktemp("benchmark_db")
    temp_db_path = temp_dir / "benchmark.db"
    source_db = "cac_grc.db.original_corrupted_bak" if os.path.exists("cac_grc.db.original_corrupted_bak") else "cac_grc.db"
    shutil.copyfile(source_db, temp_db_path)
    engine = create_engine(f"sqlite:///{temp_db_path}")
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()

def test_benchmark_all_10_scenarios_pass_assertions(db: Session):
    """
    Executes the 10-scenario EW-CES benchmark and asserts all scenario assertions hold.
    """
    output = execute_benchmark(db=db)
    summary = output["summary"]
    metadata = output["metadata"]

    assert summary["all_passed"] is True
    assert summary["scenarios_passed"] == 10
    assert summary["assertion_failures_count"] == 0
    assert summary["divergence_count"] == 3
    assert metadata["total_scenarios"] == 10

def test_benchmark_negative_test_detects_mismatch(db: Session, monkeypatch):
    """
    Negative test: Proves that if an incorrect expectation is injected into a scenario,
    the benchmark harness flags the failure and does not silently pass.
    """
    # Temporarily tamper scenario 1 expected state
    original_state = SCENARIOS[0].expected_ewces_state
    try:
        SCENARIOS[0].expected_ewces_state = "INVALID_EXPECTED_STATE"
        output = execute_benchmark(db=db)
        summary = output["summary"]

        assert summary["all_passed"] is False
        assert summary["assertion_failures_count"] >= 1
        assert output["results"][0]["passed_assertion"] is False
        assert "EW-CES mismatch" in output["results"][0]["error_message"]
    finally:
        # Restore scenario 1
        SCENARIOS[0].expected_ewces_state = original_state
