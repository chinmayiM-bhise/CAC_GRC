"""
GitRunner Deprecation Notice:
Per CAC-GRC Architectural Scope, Git/Gitea runner is deprecated and removed from core assessment targets.
The platform's core assessment scope focuses exclusively on:
1. Linux hosts assessed over SSH (SSHRunner)
2. PostgreSQL databases assessed via database connections (DBRunner)
"""

from app.engine.runner.base import BaseRunner, TestResult

class GitRunner(BaseRunner):
    """Deprecated legacy runner stub."""
    def __init__(self, *args, **kwargs):
        pass

    def execute(self, test_id: str, tier: int, test_spec: dict, allow_simulation: bool = False) -> TestResult:
        raise NotImplementedError(
            "GitRunner has been removed from CAC-GRC core scope. Core targets are Linux VM (SSH) and PostgreSQL DB."
        )
