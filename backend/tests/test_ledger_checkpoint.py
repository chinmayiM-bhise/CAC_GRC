import pytest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

from app.main import app
from app.config import settings

from app.database import Base
from app.models.base import utc_now
from app.models.evidence import EvidenceRecord
from app.engine.runner.base import TestResult
from app.engine.ledger.vault import EvidenceVault
from app.engine.ledger import checkpoint as chkpt
from app.services.ledger_service import LedgerService


@pytest.fixture
def clean_checkpoint_test_env():
    """
    Provides an isolated, in-memory database with a clean sequential evidence ledger
    and dedicated ephemeral Ed25519 signing keypair. Never alters cac_grc.db.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = Session()

    private_key, public_key = chkpt.generate_signing_keypair()

    yield {
        "db": db,
        "private_key": private_key,
        "public_key": public_key
    }

    db.close()


# =============================================================================
# 1. PUBLIC-KEY TRUST TESTS
# =============================================================================

def test_public_key_trust_replaces_payload_and_embedded_key_rejected(clean_checkpoint_test_env):
    """
    SECURITY AUDIT TEST:
    An attacker generates their own rogue Ed25519 keypair, creates a forged checkpoint,
    signs it with their rogue private key, and embeds their rogue public key in the artifact.
    The verifier MUST NOT trust the embedded key and MUST REJECT the forged checkpoint as UNTRUSTED_KEY.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    trusted_public_key = env["public_key"]

    now = utc_now()
    r = TestResult(test_id="TEST-TRUST-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": "v"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r)

    # Attacker generates completely separate, rogue keypair
    rogue_private, rogue_public = chkpt.generate_signing_keypair()

    # Attacker creates forged checkpoint signed by rogue key and embeds rogue public key
    forged_cp = chkpt.create_checkpoint(db=db, private_key=rogue_private, ledger_id="ROGUE-LEDGER")
    assert forged_cp["public_key_pem"] == chkpt.serialize_public_key_pem(rogue_public)

    # Verification against trusted anchor MUST reject the substitution
    result = chkpt.verify_checkpoint(db=db, checkpoint=forged_cp, trusted_public_key=trusted_public_key)
    assert result.is_valid is False
    assert result.status == "UNTRUSTED_KEY"
    assert any("UNTRUSTED_KEY" in v for v in result.violations)


def test_key_unavailable_rejected_when_no_trusted_key_configured(clean_checkpoint_test_env, monkeypatch):
    """
    If no trusted public key is provided by the caller or configured on the server,
    the verifier refuses to validate signatures against an untrusted embedded key.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]

    # Ensure no default public key path exists
    monkeypatch.setattr(settings, "LEDGER_VERIFY_KEY_PATH", "non_existent_key_path.pub")

    now = utc_now()
    r = TestResult(test_id="TEST-NOKEY-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": "v"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r)

    cp = chkpt.create_checkpoint(db=db, private_key=priv)

    # Verifying without supplying a trusted public key must fail closed with KEY_UNAVAILABLE
    res = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=None)
    assert res.is_valid is False
    assert res.status == "KEY_UNAVAILABLE"
    assert any("KEY_UNAVAILABLE" in v for v in res.violations)


# =============================================================================
# 2. SIGNED PAYLOAD & DIGEST RECOMPUTATION TESTS
# =============================================================================

def test_valid_checkpoint_creation_and_verification(clean_checkpoint_test_env):
    """
    Validates end-to-end creation, digest computation, and signature verification.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r1 = TestResult(test_id="TEST-CHKPT-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"chkpt": "val1"}, collected_at=now)
    r2 = TestResult(test_id="TEST-CHKPT-02", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=15, raw_telemetry={"chkpt": "val2"}, collected_at=now + datetime.timedelta(milliseconds=50))
    EvidenceVault.commit_evidence(db, r1)
    ev2 = EvidenceVault.commit_evidence(db, r2)

    cp = chkpt.create_checkpoint(db=db, private_key=priv, ledger_id="CAC-GRC-TEST-LEDGER")

    assert cp["format_version"] == "CAC-GRC-CHKPT-v1.0"
    assert cp["checkpoint_payload"]["last_record_id"] == ev2.id
    assert cp["checkpoint_payload"]["last_record_hash"] == ev2.payload_sha256
    assert cp["checkpoint_payload"]["last_record_sequence"] == 2
    assert cp["signature_algorithm"] == "Ed25519"
    assert len(cp["signature"]) == 128  # 64 bytes hex = 128 chars

    result = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=pub)
    assert result.is_valid is True
    assert result.signature_valid is True
    assert result.ledger_matched is True
    assert result.status == "VERIFIED"


def test_altered_checkpoint_payload_rejected_by_digest_recomputation(clean_checkpoint_test_env):
    """
    Verifier must recompute payload digest and detect any modification to checkpoint_payload.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r = TestResult(test_id="TEST-CHKPT-ALTER", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"chkpt": "val"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r)

    cp = chkpt.create_checkpoint(db=db, private_key=priv)

    # Mutate a payload attribute without updating checkpoint_sha256
    cp["checkpoint_payload"]["last_record_sequence"] += 999

    result = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=pub)
    assert result.is_valid is False
    assert result.status == "PAYLOAD_TAMPERED"


def test_invalid_signature_rejected(clean_checkpoint_test_env):
    """
    Corrupting signature bytes fails Ed25519 verification.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r = TestResult(test_id="TEST-CHKPT-SIG", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "ok"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r)

    cp = chkpt.create_checkpoint(db=db, private_key=priv)
    corrupted_sig = ("00" if cp["signature"][:2] != "00" else "ff") + cp["signature"][2:]
    cp["signature"] = corrupted_sig

    result = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=pub)
    assert result.is_valid is False
    assert result.signature_valid is False
    assert result.status == "INVALID_SIGNATURE"


def test_unsupported_algorithm_and_version_rejected(clean_checkpoint_test_env):
    """
    Verifier rejects unsupported signature algorithms and format versions.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r = TestResult(test_id="TEST-CHKPT-VER", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"status": "ok"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r)

    # Unsupported algorithm
    cp_bad_algo = chkpt.create_checkpoint(db=db, private_key=priv)
    cp_bad_algo["signature_algorithm"] = "RSA-MD5"
    res_algo = chkpt.verify_checkpoint(db=db, checkpoint=cp_bad_algo, trusted_public_key=pub)
    assert res_algo.is_valid is False
    assert res_algo.status == "UNSUPPORTED_ALGORITHM"

    # Unsupported version
    cp_bad_ver = chkpt.create_checkpoint(db=db, private_key=priv)
    cp_bad_ver["format_version"] = "CAC-GRC-CHKPT-v99.0"
    cp_bad_ver["checkpoint_payload"]["format_version"] = "CAC-GRC-CHKPT-v99.0"
    # Re-sign with bad version to isolate version failure
    d, b = chkpt.compute_checkpoint_digest(cp_bad_ver["checkpoint_payload"])
    cp_bad_ver["checkpoint_sha256"] = d
    cp_bad_ver["signature"] = priv.sign(b).hex()

    res_ver = chkpt.verify_checkpoint(db=db, checkpoint=cp_bad_ver, trusted_public_key=pub)
    assert res_ver.is_valid is False
    assert res_ver.status == "UNSUPPORTED_VERSION"


# =============================================================================
# 3. ROLLBACK RESISTANCE TESTS
# =============================================================================

def test_rollback_resistance_database_truncated_or_rewound(clean_checkpoint_test_env):
    """
    If the database is restored from an older backup or truncated after a checkpoint
    was issued, verification fails with ROLLBACK_DETECTED.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r1 = TestResult(test_id="TEST-RB-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"step": "1"}, collected_at=now)
    r2 = TestResult(test_id="TEST-RB-02", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"step": "2"}, collected_at=now + datetime.timedelta(milliseconds=50))
    r3 = TestResult(test_id="TEST-RB-03", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"step": "3"}, collected_at=now + datetime.timedelta(milliseconds=100))

    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)
    ev3 = EvidenceVault.commit_evidence(db, r3)

    # Issued checkpoint anchors sequence 3
    cp_seq3 = chkpt.create_checkpoint(db=db, private_key=priv)
    assert cp_seq3["checkpoint_payload"]["last_record_sequence"] == 3

    # Attacker rewinds / deletes recent record 3 (simulating DB rollback to sequence 2)
    db.delete(ev3)
    db.commit()

    # Verifying the valid checkpoint 3 against the rolled-back DB must detect rollback
    res = chkpt.verify_checkpoint(db=db, checkpoint=cp_seq3, trusted_public_key=pub)
    assert res.is_valid is False
    assert res.status == "ROLLBACK_DETECTED"
    assert any("ROLLBACK_DETECTED" in v for v in res.violations)


def test_rollback_resistance_against_newer_trusted_checkpoint_sequence(clean_checkpoint_test_env):
    """
    An auditor with knowledge of sequence N rejects an attacker presenting an older checkpoint (sequence N-k).
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r1 = TestResult(test_id="TEST-SEQ-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": 1}, collected_at=now)
    EvidenceVault.commit_evidence(db, r1)
    cp_seq1 = chkpt.create_checkpoint(db=db, private_key=priv)

    r2 = TestResult(test_id="TEST-SEQ-02", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": 2}, collected_at=now + datetime.timedelta(milliseconds=50))
    EvidenceVault.commit_evidence(db, r2)
    cp_seq2 = chkpt.create_checkpoint(db=db, private_key=priv)

    # Auditor already holds cp_seq2 (sequence = 2). Attacker replays cp_seq1 (sequence = 1).
    res = chkpt.verify_checkpoint(db=db, checkpoint=cp_seq1, trusted_public_key=pub, min_expected_sequence=2)
    assert res.is_valid is False
    assert res.status == "ROLLBACK_DETECTED"
    assert any("is older than minimum expected sequence" in v for v in res.violations)


# =============================================================================
# 4. RECORD CONSISTENCY & LINKAGE TESTS
# =============================================================================

def test_record_consistency_equal_timestamps_preserve_strict_insertion_order(clean_checkpoint_test_env):
    """
    Verifies that records committed with the exact same millisecond timestamp
    are ordered strictly and deterministically by insertion sequence (rowid) without breaking chain linkage.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    identical_now = utc_now()
    r1 = TestResult(test_id="TEST-EQTS-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"t": 1}, collected_at=identical_now)
    r2 = TestResult(test_id="TEST-EQTS-02", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"t": 2}, collected_at=identical_now)
    r3 = TestResult(test_id="TEST-EQTS-03", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"t": 3}, collected_at=identical_now)

    EvidenceVault.commit_evidence(db, r1)
    EvidenceVault.commit_evidence(db, r2)
    ev3 = EvidenceVault.commit_evidence(db, r3)

    cp = chkpt.create_checkpoint(db=db, private_key=priv)
    assert cp["checkpoint_payload"]["last_record_sequence"] == 3
    assert cp["checkpoint_payload"]["last_record_id"] == ev3.id

    res = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=pub)
    assert res.is_valid is True
    assert res.status == "VERIFIED"


def test_record_consistency_missing_or_out_of_order_records_break_chain(clean_checkpoint_test_env):
    """
    Deleting an intermediate record breaks the sequential hash chain up to the checkpoint.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r1 = TestResult(test_id="TEST-BREAK-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": 1}, collected_at=now)
    r2 = TestResult(test_id="TEST-BREAK-02", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": 2}, collected_at=now + datetime.timedelta(milliseconds=50))
    r3 = TestResult(test_id="TEST-BREAK-03", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": 3}, collected_at=now + datetime.timedelta(milliseconds=100))

    EvidenceVault.commit_evidence(db, r1)
    ev2 = EvidenceVault.commit_evidence(db, r2)
    ev3 = EvidenceVault.commit_evidence(db, r3)

    cp = chkpt.create_checkpoint(db=db, private_key=priv)

    # Delete intermediate record 2
    db.delete(ev2)
    db.commit()

    res = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=pub)
    assert res.is_valid is False
    assert res.status in ("LEDGER_INTEGRITY_COMPROMISED", "ROLLBACK_DETECTED")


def test_record_consistency_appended_records_allow_historical_checkpoint_verification(clean_checkpoint_test_env):
    """
    Appending new records after a checkpoint does NOT invalidate historical checkpoints.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r1 = TestResult(test_id="TEST-APP-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": 1}, collected_at=now)
    ev1 = EvidenceVault.commit_evidence(db, r1)

    # Create checkpoint at sequence 1
    cp_seq1 = chkpt.create_checkpoint(db=db, private_key=priv)

    # Append subsequent records
    r2 = TestResult(test_id="TEST-APP-02", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=2, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": 2}, collected_at=now + datetime.timedelta(milliseconds=50))
    EvidenceVault.commit_evidence(db, r2)

    # Checkpoint 1 remains valid for its historical horizon
    res = chkpt.verify_checkpoint(db=db, checkpoint=cp_seq1, trusted_public_key=pub)
    assert res.is_valid is True
    assert res.status == "VERIFIED"


# =============================================================================
# 5. KEY LIFECYCLE & HYGIENE TESTS
# =============================================================================

def test_key_lifecycle_private_key_never_exposed_or_regenerated_in_verification(clean_checkpoint_test_env):
    """
    Confirm private keys are never exposed in checkpoint artifacts, verification responses,
    or generated/modified during verification operations.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    now = utc_now()
    r = TestResult(test_id="TEST-HYGIENE-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"k": "v"}, collected_at=now)
    EvidenceVault.commit_evidence(db, r)

    cp = chkpt.create_checkpoint(db=db, private_key=priv)

    # 1. Private key must not exist anywhere in artifact
    cp_json_str = str(cp)
    assert "PRIVATE" not in cp_json_str
    assert "BEGIN PRIVATE KEY" not in cp_json_str

    # 2. Verify operation must not modify keys or return private key material
    res = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=pub)
    res_str = str(res)
    assert "PRIVATE" not in res_str
    assert res.is_valid is True


# =============================================================================
# 6. GENESIS ANCHOR & API TESTS
# =============================================================================

def test_empty_ledger_genesis_anchor_verification(clean_checkpoint_test_env):
    """
    A checkpoint created when ledger has zero records generates a valid genesis anchor.
    """
    env = clean_checkpoint_test_env
    db = env["db"]
    priv = env["private_key"]
    pub = env["public_key"]

    cp = chkpt.create_checkpoint(db=db, private_key=priv, ledger_id="CAC-GRC-EMPTY-TEST")
    assert cp["checkpoint_payload"]["last_record_id"] is None
    assert cp["checkpoint_payload"]["last_record_sequence"] == 0
    assert cp["checkpoint_payload"]["last_record_hash"] == "0" * 64

    res = chkpt.verify_checkpoint(db=db, checkpoint=cp, trusted_public_key=pub)
    assert res.is_valid is True
    assert res.status == "VERIFIED"


def test_checkpoint_api_endpoints_rbac_and_flow(monkeypatch):
    """
    Validates HTTP API endpoints:
    - POST /api/v1/ledger/checkpoint requires admin role.
    - POST /api/v1/ledger/checkpoint/verify accessible to auditor role.
    """
    admin_tok = "test-chkpt-admin-token"
    aud_tok = "test-chkpt-auditor-token"
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "DEV_AUTH_BYPASS", False)
    monkeypatch.setattr(settings, "CAC_ADMIN_TOKEN", admin_tok)
    monkeypatch.setattr(settings, "CAC_AUDITOR_TOKEN", aud_tok)

    client = TestClient(app)

    # 1. Unauthenticated request to checkpoint generation fails with 401
    r_unauth = client.post("/api/v1/ledger/checkpoint")
    assert r_unauth.status_code == 401

    # 2. Auditor attempting to create checkpoint fails with 403
    r_aud_create = client.post(
        "/api/v1/ledger/checkpoint",
        headers={"Authorization": f"Bearer {aud_tok}"}
    )
    assert r_aud_create.status_code == 403

    # 3. Admin successfully creates checkpoint (200)
    r_admin_create = client.post(
        "/api/v1/ledger/checkpoint",
        headers={"Authorization": f"Bearer {admin_tok}"}
    )
    assert r_admin_create.status_code == 200
    cp_data = r_admin_create.json()
    assert cp_data["format_version"] == "CAC-GRC-CHKPT-v1.0"
    assert "signature" in cp_data
    assert "checkpoint_sha256" in cp_data

    # 4. Auditor can verify checkpoint (200)
    r_verify = client.post(
        "/api/v1/ledger/checkpoint/verify",
        json=cp_data,
        headers={"Authorization": f"Bearer {aud_tok}"}
    )
    assert r_verify.status_code == 200
    ver_data = r_verify.json()
    assert "is_valid" in ver_data
    assert ver_data["signature_valid"] is True


def test_backward_compatibility_with_existing_vault_and_assessments(clean_checkpoint_test_env):
    """
    Preserves existing EvidenceVault methods and LedgerService APIs without breaking existing functionality.
    """
    env = clean_checkpoint_test_env
    db = env["db"]

    now = utc_now()
    r = TestResult(test_id="TEST-COMPAT-01", result_code=1, execution_status="SUCCESS", evidence_provenance="LIVE_TARGET", tier=1, target_type="LINUX_VM", duration_ms=10, raw_telemetry={"setting": "pass"}, collected_at=now)
    rec = EvidenceVault.commit_evidence(db, r)
    assert rec.id is not None

    is_valid, violations = EvidenceVault.verify_ledger_integrity(db)
    assert isinstance(is_valid, bool)

    summary = LedgerService.get_ledger_summary(db)
    assert "ledger_intact" in summary
