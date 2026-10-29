"""
CAC-GRC Ledger & Evidence Integrity Service.
Provides cryptographic verification, hash-link auditing, and evidence queries.
"""

from typing import Dict, Any, List, Optional, Union
import os
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.models.evidence import EvidenceRecord
from app.engine.ledger.vault import EvidenceVault
from app.engine.ledger import checkpoint as chkpt
from app.config import settings


class LedgerService:
    @staticmethod
    def verify_ledger(db: Session) -> Dict[str, Any]:
        """
        Performs full cryptographic audit over all records in the sequential hash-linked ledger:
        1. Checks each record's SHA-256 payload digest matches raw telemetry and attributes.
        2. Checks each record's prev_hash matches the previous record's payload_sha256.
        Returns detailed report including index and record ID of any violation.
        """
        is_intact, violations = EvidenceVault.verify_ledger_integrity(db)
        total_records = db.query(EvidenceRecord).count()

        return {
            "ledger_intact": is_intact,
            "total_records": total_records,
            "violations_count": len(violations),
            "violations": violations
        }

    @staticmethod
    def list_evidence(
        db: Session,
        test_id: Optional[str] = None,
        limit: int = 50
    ) -> List[EvidenceRecord]:
        query = db.query(EvidenceRecord)
        if test_id:
            query = query.filter(EvidenceRecord.test_id == test_id)
        return query.order_by(EvidenceRecord.created_at.desc()).limit(limit).all()

    @staticmethod
    def get_ledger_summary(db: Session) -> Dict[str, Any]:
        """Provides quick summary of ledger state for UI banner and audit exports."""
        total = db.query(EvidenceRecord).count()
        latest = db.query(EvidenceRecord).order_by(EvidenceRecord.created_at.desc()).first()
        is_intact, violations = EvidenceVault.verify_ledger_integrity(db)

        return {
            "total_records": total,
            "latest_record_id": latest.id if latest else None,
            "latest_hash": latest.payload_sha256 if latest else None,
            "ledger_intact": is_intact,
            "violations": violations
        }

    @classmethod
    def create_checkpoint(
        cls,
        db: Session,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        ledger_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates and signs a canonical cryptographic checkpoint anchoring the current ledger state.
        Uses provided private key, or securely loads/initializes the configured keypair on disk.
        """
        lid = ledger_id or getattr(settings, "LEDGER_ID", chkpt.DEFAULT_LEDGER_ID)

        if private_key is None:
            priv_path = getattr(settings, "LEDGER_SIGNING_KEY_PATH", "keys/ledger_ed25519_private.pem")
            pub_path = getattr(settings, "LEDGER_VERIFY_KEY_PATH", "keys/ledger_ed25519_public.pem")

            if priv_path and os.path.exists(priv_path):
                with open(priv_path, "rb") as f:
                    private_key = chkpt.load_private_key_pem(f.read())
            else:
                # Generate new dedicated signing keypair
                private_key, public_key = chkpt.generate_signing_keypair()
                if priv_path and pub_path:
                    chkpt.save_keypair(private_key, public_key, priv_path, pub_path)

        return chkpt.create_checkpoint(db=db, private_key=private_key, ledger_id=lid)

    @classmethod
    def verify_checkpoint(
        cls,
        db: Session,
        checkpoint_data: Dict[str, Any],
        public_key: Optional[Union[ed25519.Ed25519PublicKey, str]] = None,
        min_expected_sequence: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Validates external checkpoint against digital signature and local ledger state.
        Enforces that public keys must come from trusted configuration or caller, never from the untrusted artifact alone.
        """
        if public_key is None:
            pub_path = getattr(settings, "LEDGER_VERIFY_KEY_PATH", "keys/ledger_ed25519_public.pem")
            if pub_path and os.path.exists(pub_path):
                with open(pub_path, "rb") as f:
                    public_key = chkpt.load_public_key_pem(f.read())

        result = chkpt.verify_checkpoint(
            db=db,
            checkpoint=checkpoint_data,
            trusted_public_key=public_key,
            min_expected_sequence=min_expected_sequence
        )
        return {
            "is_valid": result.is_valid,
            "signature_valid": result.signature_valid,
            "ledger_matched": result.ledger_matched,
            "status": result.status,
            "violations": result.violations,
            "checkpoint_summary": result.checkpoint_summary
        }
