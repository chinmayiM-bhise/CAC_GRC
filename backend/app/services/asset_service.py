"""
CAC-GRC Monitored Asset Service.
Provides enterprise asset reachability probing without exposing credentials,
and clearly separates live reachability status from historical evidence provenance.
"""

import socket
from urllib.parse import urlparse
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import settings
from app.models.evidence import EvidenceRecord
from app.models.test_definition import TestDefinition
from app.models.assessment import AssessmentRun


class AssetService:
    @staticmethod
    def probe_socket(host: str, port: int, timeout: float = 0.3) -> bool:
        """Non-destructive TCP socket probe."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    @staticmethod
    def probe_url(url: str, timeout: float = 0.3) -> bool:
        """Non-destructive HTTP URL host probe."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or "localhost"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    @classmethod
    def list_monitored_assets(cls, db: Session) -> List[Dict[str, Any]]:
        """
        Returns registered lab target assets.
        Includes real-time connectivity status and links to historical evidence
        without leaking passwords, tokens, or private keys.
        """
        # Historical stats from database via joined TestDefinition
        def get_ev_stats(target_type_str: str):
            q = db.query(EvidenceRecord).join(
                TestDefinition,
                EvidenceRecord.test_id == TestDefinition.test_id
            ).filter(TestDefinition.target_type == target_type_str)
            count = q.count()
            latest = q.order_by(EvidenceRecord.created_at.desc()).first()
            return count, (latest.created_at.isoformat() if latest else None)

        vm_count, vm_latest = get_ev_stats("LINUX_VM")
        db_count, db_latest = get_ev_stats("POSTGRES_DB")

        assets = [
            {
                "id": "asset-vm-01",
                "name": "Ubuntu Enterprise Server",
                "type": "LINUX_VM",
                "host": settings.LINUX_VM_HOST,
                "port": settings.LINUX_VM_PORT,
                "role": "Operating System Baseline (PAM, auditd, SSH)",
                "auth_method": "SSH Key / Password (Configured)",
                "status": "ONLINE" if cls.probe_socket(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT) else "OFFLINE",
                "current_connectivity": "ONLINE" if cls.probe_socket(settings.LINUX_VM_HOST, settings.LINUX_VM_PORT) else "OFFLINE",
                "historical_evidence_count": vm_count,
                "last_evidence_at": vm_latest
            },
            {
                "id": "asset-db-01",
                "name": "PostgreSQL 16 Cluster",
                "type": "POSTGRES_DB",
                "host": settings.TARGET_DB_HOST,
                "port": settings.TARGET_DB_PORT,
                "role": "Enterprise Data Store (Least Privilege, TLS Enforcement)",
                "auth_method": "PostgreSQL Native Wire Protocol (TLS)",
                "status": "ONLINE" if cls.probe_socket(settings.TARGET_DB_HOST, settings.TARGET_DB_PORT) else "OFFLINE",
                "current_connectivity": "ONLINE" if cls.probe_socket(settings.TARGET_DB_HOST, settings.TARGET_DB_PORT) else "OFFLINE",
                "historical_evidence_count": db_count,
                "last_evidence_at": db_latest
            }
        ]
        return assets
