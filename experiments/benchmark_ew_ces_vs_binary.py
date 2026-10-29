"""
CAC-GRC Research Experiment: EW-CES vs. Traditional Binary Scoring Across 10 Scenarios.

Empirical comparison between:
1. Traditional Binary Scoring: Legacy GRC model evaluating controls as binary PASS/FAIL
   based solely on latest recorded exit codes, ignoring evidence age, behavioral probe
   coverage, and cryptographic ledger integrity.
2. Evidence-Weighted Control Effectiveness Scoring (EW-CES): 4-state assurance model
   (VERIFIED_EFFECTIVE, CONFIG_COMPLIANT_EFFECTIVENESS_UNVERIFIED, DEFICIENT, UNKNOWN)
   incorporating temporal decay (TTL), multi-tier test requirements, and SHA-256 hash chaining.
"""

import sys
import os
import json
import platform
import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Callable

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.database import SessionLocal
from app.models.framework import FrameworkControl
from app.models.mapping import PolicyMapping
from app.models.test_definition import TestDefinition
from app.models.evidence import EvidenceRecord
from app.models.base import utc_now
from app.engine.scoring.classifier import (
    EWCESClassifier,
    STATE_VERIFIED_EFFECTIVE,
    STATE_CONFIG_COMPLIANT_UNVERIFIED,
    STATE_DEFICIENT,
    STATE_UNKNOWN
)
from app.engine.ledger.vault import EvidenceVault
from app.engine.runner.base import TestResult
from app.engine.ledger.hasher import compute_evidence_hash
from app.engine.scoring.decay import ensure_utc

BENCHMARK_VERSION = "2.1.0-reproducible"

# -------------------------------------------------------------------------
# TYPED SCENARIO SCHEMA
# -------------------------------------------------------------------------
@dataclass
class BenchmarkScenario:
    """Typed specification for a benchmark evaluation scenario."""
    scenario_id: int
    name: str
    description: str
    expected_ewces_state: str
    expected_binary_status: str
    expected_divergence: bool
    rationale: str


@dataclass
class ScenarioExecutionResult:
    """Outcome of an executed benchmark scenario with assertion status."""
    scenario_id: int
    name: str
    expected_ewces_state: str
    actual_ewces_state: str
    expected_binary_status: str
    actual_binary_status: str
    expected_divergence: bool
    actual_divergence: bool
    freshness: float
    diagnostic_summary: str
    passed_assertion: bool
    error_message: Optional[str] = None


# -------------------------------------------------------------------------
# TRADITIONAL BINARY SCORER (BASELINE MODEL)
# -------------------------------------------------------------------------
class TraditionalBinaryScorer:
    """
    Standard GRC baseline model commonly used by legacy assessment tools.
    
    Documented baseline rules:
    - Evaluates controls as binary PASSED or FAILED based solely on the latest exit code.
    - Result code 1 = PASSED (100% compliance).
    - Result code -1 = FAILED (0% compliance).
    - Result code 0 / errors = INCONCLUSIVE (or UNKNOWN if no data).
    - Ignores evidence age / TTL expiration (assumes old pass is still valid).
    - Ignores behavioral testing requirements (treats config check as sufficient for 100%).
    - Ignores cryptographic hash ledger integrity (unaware of payload tampering).
    """

    @classmethod
    def evaluate(cls, db, control_id: str) -> Dict[str, Any]:
        mappings = db.query(PolicyMapping).filter_by(control_id=control_id).all()
        mapping_ids = [m.id for m in mappings]
        test_defs = db.query(TestDefinition).filter(TestDefinition.mapping_id.in_(mapping_ids)).all()

        if not test_defs:
            return {"status": "UNKNOWN", "score_pct": 0.0, "is_compliant": False}

        results = []
        for t in test_defs:
            ev = db.query(EvidenceRecord).filter_by(test_id=t.test_id).order_by(EvidenceRecord.created_at.desc()).first()
            if ev:
                results.append(ev.result_code)

        if not results:
            return {"status": "UNKNOWN", "score_pct": 0.0, "is_compliant": False}

        has_failure = any(r == -1 for r in results)
        has_pass = any(r == 1 for r in results)

        if has_failure:
            return {"status": "FAILED", "score_pct": 0.0, "is_compliant": False}
        elif has_pass:
            return {"status": "PASSED", "score_pct": 100.0, "is_compliant": True}
        else:
            return {"status": "INCONCLUSIVE", "score_pct": 0.0, "is_compliant": False}


# -------------------------------------------------------------------------
# THE 10 FORMALIZED BENCHMARK SCENARIOS
# -------------------------------------------------------------------------
SCENARIOS: List[BenchmarkScenario] = [
    BenchmarkScenario(
        scenario_id=1,
        name="1. Fully Verified Baseline",
        description="Fresh Tier 1 config pass and fresh Tier 2 behavioral pass committed with intact ledger hashes.",
        expected_ewces_state=STATE_VERIFIED_EFFECTIVE,
        expected_binary_status="PASSED",
        expected_divergence=False,
        rationale="Both models agree: control is operational and verified."
    ),
    BenchmarkScenario(
        scenario_id=2,
        name="2. Confirmed Config Failure",
        description="Tier 1 config probe reports failure (result_code = -1).",
        expected_ewces_state=STATE_DEFICIENT,
        expected_binary_status="FAILED",
        expected_divergence=False,
        rationale="Both models agree: configuration violation caught."
    ),
    BenchmarkScenario(
        scenario_id=3,
        name="3. Confirmed Behavioral Failure",
        description="Tier 1 config passes, but Tier 2 behavioral probe confirms failure (result_code = -1).",
        expected_ewces_state=STATE_DEFICIENT,
        expected_binary_status="FAILED",
        expected_divergence=False,
        rationale="Both models flag failure because negative exit code is present."
    ),
    BenchmarkScenario(
        scenario_id=4,
        name="4. Stale Evidence (>TTL)",
        description="Valid passing evidence collected 48 hours ago (TTL is 24 hours).",
        expected_ewces_state=STATE_UNKNOWN,
        expected_binary_status="PASSED",
        expected_divergence=True,
        rationale="Divergence: Traditional GRC treats stale pass as 100% compliant; EW-CES flags UNKNOWN due to TTL expiration."
    ),
    BenchmarkScenario(
        scenario_id=5,
        name="5. Missing Evidence",
        description="No evidence records exist for the control tests.",
        expected_ewces_state=STATE_UNKNOWN,
        expected_binary_status="UNKNOWN",
        expected_divergence=False,
        rationale="Both models recognize absence of any telemetry."
    ),
    BenchmarkScenario(
        scenario_id=6,
        name="6. Inaccessible Target / Error",
        description="Target host was unreachable, runner recorded result_code = 0 and CONNECTION_ERROR.",
        expected_ewces_state=STATE_UNKNOWN,
        expected_binary_status="INCONCLUSIVE",
        expected_divergence=False,
        rationale="Neither model claims compliance; EW-CES treats as UNKNOWN."
    ),
    BenchmarkScenario(
        scenario_id=7,
        name="7. Conflicting Evidence",
        description="Config passes (1) but behavioral probe reports failure (-1).",
        expected_ewces_state=STATE_DEFICIENT,
        expected_binary_status="FAILED",
        expected_divergence=False,
        rationale="Strict precedence: Confirmed failure overrules configuration pass."
    ),
    BenchmarkScenario(
        scenario_id=8,
        name="8. Tampered Evidence Ledger",
        description="Evidence record in database had raw telemetry modified post-hoc without valid hash update.",
        expected_ewces_state=STATE_UNKNOWN,
        expected_binary_status="PASSED",
        expected_divergence=True,
        rationale="Divergence: Traditional GRC blindly reads result_code=1; EW-CES detects SHA-256 mismatch and flags UNKNOWN."
    ),
    BenchmarkScenario(
        scenario_id=9,
        name="9. Partial Test Coverage",
        description="Tier 1 config check passed, but mandatory Tier 2 behavioral probe was never run.",
        expected_ewces_state=STATE_CONFIG_COMPLIANT_UNVERIFIED,
        expected_binary_status="PASSED",
        expected_divergence=True,
        rationale="Divergence: Traditional GRC awards 100% pass; EW-CES correctly isolates state to CONFIG_COMPLIANT_EFFECTIVENESS_UNVERIFIED."
    ),
    BenchmarkScenario(
        scenario_id=10,
        name="10. Restored Baseline Post-Drift",
        description="Post-remediation run with fresh passing Tier 1 and Tier 2 probes.",
        expected_ewces_state=STATE_VERIFIED_EFFECTIVE,
        expected_binary_status="PASSED",
        expected_divergence=False,
        rationale="Both models agree: remediation validated."
    ),
]


# -------------------------------------------------------------------------
# BENCHMARK EXECUTION ENGINE
# -------------------------------------------------------------------------
def execute_benchmark(db=None) -> Dict[str, Any]:
    """
    Executes all 10 benchmark scenarios against the database.
    Evaluates EW-CES and Traditional Binary baseline, asserts all expectations,
    and returns a structured, serializable result dictionary.
    """
    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True

    control_id = "NIST-AC-7"
    t1_id = "TEST-VM-PAM-LOCKOUT-T1"
    t2_id = "TEST-VM-PAM-LOCKOUT-T2"

    def clear_evidence():
        db.query(EvidenceRecord).filter(EvidenceRecord.test_id.in_([t1_id, t2_id])).delete()
        db.commit()

    results: List[ScenarioExecutionResult] = []
    all_passed = True

    try:
        for scenario in SCENARIOS:
            clear_evidence()
            eval_time = None

            # Setup scenario state
            if scenario.scenario_id in (1, 10):
                now = utc_now()
                r1 = TestResult(test_id=t1_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
                r2 = TestResult(test_id=t2_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
                EvidenceVault.commit_evidence(db, r1)
                EvidenceVault.commit_evidence(db, r2)

            elif scenario.scenario_id == 2:
                now = utc_now()
                r1 = TestResult(test_id=t1_id, result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=999"}, collected_at=now)
                r2 = TestResult(test_id=t2_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
                EvidenceVault.commit_evidence(db, r1)
                EvidenceVault.commit_evidence(db, r2)

            elif scenario.scenario_id in (3, 7):
                now = utc_now()
                r1 = TestResult(test_id=t1_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
                r2 = TestResult(test_id=t2_id, result_code=-1, execution_status="FAILURE", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": False}, collected_at=now)
                EvidenceVault.commit_evidence(db, r1)
                EvidenceVault.commit_evidence(db, r2)

            elif scenario.scenario_id == 4:
                now = utc_now()
                r1 = TestResult(test_id=t1_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
                r2 = TestResult(test_id=t2_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
                EvidenceVault.commit_evidence(db, r1)
                EvidenceVault.commit_evidence(db, r2)
                eval_time = now + datetime.timedelta(hours=48)

            elif scenario.scenario_id == 5:
                pass  # No evidence

            elif scenario.scenario_id == 6:
                now = utc_now()
                r1 = TestResult(test_id=t1_id, result_code=0, execution_status="CONNECTION_ERROR", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"error": "Connection timed out"}, collected_at=now)
                EvidenceVault.commit_evidence(db, r1)

            elif scenario.scenario_id == 8:
                now = utc_now()
                r1 = TestResult(test_id=t1_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
                rec = EvidenceVault.commit_evidence(db, r1)
                rec.raw_telemetry = {"status": "TAMPERED_MODIFIED_CONTENT"}
                db.commit()

            elif scenario.scenario_id == 9:
                now = utc_now()
                r1 = TestResult(test_id=t1_id, result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
                EvidenceVault.commit_evidence(db, r1)

            # Evaluate with EW-CES and Binary Scorer
            ew_ces_score = EWCESClassifier.evaluate_control(db, control_id, now=eval_time)
            binary_result = TraditionalBinaryScorer.evaluate(db, control_id)

            actual_ewces = ew_ces_score.state
            actual_binary = binary_result["status"]
            actual_divergence = (actual_binary == "PASSED" and actual_ewces != STATE_VERIFIED_EFFECTIVE)

            # Executable Assertions
            passed = True
            error_msg = None
            try:
                assert actual_ewces == scenario.expected_ewces_state, (
                    f"EW-CES mismatch for scenario {scenario.scenario_id} '{scenario.name}': "
                    f"expected '{scenario.expected_ewces_state}', got '{actual_ewces}'"
                )
                assert actual_binary == scenario.expected_binary_status, (
                    f"Binary status mismatch for scenario {scenario.scenario_id} '{scenario.name}': "
                    f"expected '{scenario.expected_binary_status}', got '{actual_binary}'"
                )
                assert actual_divergence == scenario.expected_divergence, (
                    f"Divergence mismatch for scenario {scenario.scenario_id} '{scenario.name}': "
                    f"expected {scenario.expected_divergence}, got {actual_divergence}"
                )
            except AssertionError as exc:
                passed = False
                all_passed = False
                error_msg = str(exc)

            results.append(ScenarioExecutionResult(
                scenario_id=scenario.scenario_id,
                name=scenario.name,
                expected_ewces_state=scenario.expected_ewces_state,
                actual_ewces_state=actual_ewces,
                expected_binary_status=scenario.expected_binary_status,
                actual_binary_status=actual_binary,
                expected_divergence=scenario.expected_divergence,
                actual_divergence=actual_divergence,
                freshness=ew_ces_score.freshness_score,
                diagnostic_summary=ew_ces_score.diagnostic_summary,
                passed_assertion=passed,
                error_message=error_msg
            ))

        # Restore clean baseline
        clear_evidence()
        now = utc_now()
        r1 = TestResult(test_id=t1_id, result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "deny=5"}, collected_at=now)
        r2 = TestResult(test_id=t2_id, result_code=1, execution_status="SUCCESS", evidence_provenance="SIMULATED_LAB", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"lockout_verified": True}, collected_at=now)
        EvidenceVault.commit_evidence(db, r1)
        EvidenceVault.commit_evidence(db, r2)
        db.commit()

    finally:
        if own_session:
            db.close()

    # Metadata and summary
    divergence_count = sum(1 for r in results if r.actual_divergence)
    assertion_failures = [r for r in results if not r.passed_assertion]

    return {
        "metadata": {
            "benchmark_version": BENCHMARK_VERSION,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "target_control_id": control_id,
            "total_scenarios": len(SCENARIOS)
        },
        "summary": {
            "all_passed": all_passed,
            "scenarios_passed": len(results) - len(assertion_failures),
            "assertion_failures_count": len(assertion_failures),
            "divergence_count": divergence_count,
            "divergence_rate": round(divergence_count / len(SCENARIOS), 2)
        },
        "results": [asdict(r) for r in results]
    }


def main():
    print("=" * 95)
    print("RESEARCH EXPERIMENT: EW-CES vs. TRADITIONAL BINARY SCORING (10 FORMAL SCENARIOS)")
    print("=" * 95)
    print("Baseline Model: Latest Exit Code (ignores TTL decay, behavioral tier, and ledger tampering).")
    print("Evaluator: Production EWCESClassifier with strict precedence and SHA-256 integrity.")
    print("-" * 95)

    benchmark_output = execute_benchmark()
    metadata = benchmark_output["metadata"]
    summary = benchmark_output["summary"]
    results = benchmark_output["results"]

    print(f"{'Condition Evaluated':<32} | {'Traditional GRC':<16} | {'EW-CES 4-State':<32} | {'Assertion'}")
    print("-" * 95)
    for r in results:
        status_flag = "[PASS]" if r["passed_assertion"] else f"[FAIL: {r['error_message']}]"
        div_flag = " (DIVERGENCE)" if r["actual_divergence"] else ""
        print(f"{r['name']:<32} | {r['actual_binary_status']:<16} | {r['actual_ewces_state']:<32} | {status_flag}{div_flag}")
    print("=" * 95)

    print(f"\nExecution Metadata:")
    print(f"  Version: {metadata['benchmark_version']}")
    print(f"  Timestamp: {metadata['timestamp_utc']}")
    print(f"  Python: {metadata['python_version']} on {metadata['platform']}")
    print(f"  Assertions Passed: {summary['scenarios_passed']}/{metadata['total_scenarios']}")
    print(f"  Empirical Divergence Rate: {summary['divergence_count']}/{metadata['total_scenarios']} ({summary['divergence_rate']*100:.0f}%)")
    print(f"  All Assertions Satisfied: {summary['all_passed']}")

    if not summary["all_passed"]:
        print("\n[!] FATAL: Benchmark assertion failures detected!")
        for r in results:
            if not r["passed_assertion"]:
                print(f"  - {r['name']}: {r['error_message']}")
        sys.exit(1)

    print("\n[+] Benchmark completed successfully with zero hardcoded outcomes.\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
