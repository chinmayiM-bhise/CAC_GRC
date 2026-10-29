from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import datetime
import re

SENSITIVE_KEY_PATTERN = re.compile(r'(password|token|secret|api[_-]?key|auth|bearer|private[_-]?key)', re.IGNORECASE)
URI_CREDENTIAL_PATTERN = re.compile(r'([a-zA-Z0-9+.-]+://[^:]+:)([^@]+)(@.+)')


def redact_secrets_from_string(text: str) -> str:
    """
    Masks inline credentials, tokens, and passwords inside arbitrary text and error traces.
    """
    if not isinstance(text, str):
        return str(text)

    # Mask URI user:pass@host
    redacted = URI_CREDENTIAL_PATTERN.sub(r'\1***\3', text)
    # Mask Bearer tokens
    redacted = re.sub(r'(Bearer\s+)[a-zA-Z0-9_\-\.]+', r'\1[REDACTED]', redacted, flags=re.IGNORECASE)
    # Mask password=... or token=...
    redacted = re.sub(
        r'((?:password|token|secret|key)\s*[:=]\s*["\']?)([^"\'\s,;]+)(["\']?)',
        r'\1[REDACTED]\3',
        redacted,
        flags=re.IGNORECASE
    )
    return redacted


def sanitize_telemetry(data: Any) -> Any:
    """
    Recursively scans and redacts sensitive keys and values from telemetry data structures.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_telemetry(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_telemetry(item) for item in data]
    elif isinstance(data, str):
        return redact_secrets_from_string(data)
    return data


@dataclass
class TestResult:
    """
    Normalized observation schema across all agentless assessment runners.
    Explicitly distinguishes live observations from simulated telemetry.
    """
    __test__ = False  # Prevent pytest collection

    test_id: str
    result_code: int  # 1 = Pass, -1 = Fail, 0 = Inconclusive / Error
    execution_status: str  # SUCCESS, FAILURE, CONNECTION_ERROR, TIMEOUT, SIMULATED, HOST_KEY_VERIFICATION_FAILED
    evidence_provenance: str  # LIVE_TARGET, SIMULATED_LAB, CACHED
    tier: int  # 1 = Static Config Check, 2 = Behavioral Probe
    target_type: str  # LINUX_VM, POSTGRES_DB, GITEA_VCS
    duration_ms: int
    raw_telemetry: Dict[str, Any]
    collected_at: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    error_message: Optional[str] = None

    def __post_init__(self):
        # Automatically redact sensitive telemetry and error messages upon initialization
        if self.raw_telemetry:
            self.raw_telemetry = sanitize_telemetry(self.raw_telemetry)
        if self.error_message:
            self.error_message = redact_secrets_from_string(self.error_message)


class BaseRunner(ABC):
    """Abstract interface for agentless compliance test executors."""

    @abstractmethod
    def execute(self, test_id: str, tier: int, test_spec: Dict[str, Any], allow_simulation: bool = False) -> TestResult:
        """
        Executes a test specification against the target environment.
        Never silently converts connection errors into PASS.
        """
        pass
