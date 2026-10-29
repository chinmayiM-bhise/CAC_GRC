from pathlib import Path
from typing import Optional, List
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Canonical project root directory (contains backend, keys, lab, etc.)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DOTENV_PATH = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    PROJECT_NAME: str = "CAC-GRC Engine"
    API_V1_STR: str = "/api/v1"

    # Environment Mode: 'development' or 'production'
    ENVIRONMENT: str = "development"

    # Database Settings (defaults to local SQLite for local development; can switch to PostgreSQL)
    DATABASE_URL: str = "sqlite:///./cac_grc.db"

    # Authentication & Role-Based Access Control (RBAC)
    AUTH_ENABLED: bool = True
    # Isolated local-development authentication bypass (allows seamless core workflow without login)
    # Strictly disabled in production via model_validator
    DEV_AUTH_BYPASS: bool = True
    CAC_ADMIN_TOKEN: Optional[str] = "admin-token-cac-2026"
    CAC_ENGINEER_TOKEN: Optional[str] = "engineer-token-cac-2026"
    CAC_AUDITOR_TOKEN: Optional[str] = "auditor-token-cac-2026"

    # CORS Allowed Origins
    CORS_ALLOWED_ORIGINS: List[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Target 1: Linux VM Connection Settings
    LINUX_VM_HOST: str = "192.168.56.101"
    LINUX_VM_PORT: int = 22
    LINUX_VM_USER: str = "auditor"
    LINUX_VM_KEY_PATH: Optional[str] = None
    LINUX_VM_PASSWORD: Optional[str] = None
    SSH_KNOWN_HOSTS_FILE: Optional[str] = "lab/vm-setup/known_hosts"
    SSH_STRICT_HOST_KEY_CHECKING: bool = True

    # Target 2: Target PostgreSQL Container Settings
    TARGET_DB_HOST: str = "localhost"
    TARGET_DB_PORT: int = 5433
    TARGET_DB_USER: str = "postgres"
    TARGET_DB_PASSWORD: Optional[str] = None
    TARGET_DB_NAME: str = "enterprisedb"

    # Stage D1: External Ledger Integrity & Asymmetric Checkpointing
    LEDGER_ID: str = "CAC-GRC-PRIMARY-LEDGER"
    LEDGER_SIGNING_KEY_PATH: Optional[str] = "keys/ledger_ed25519_private.pem"
    LEDGER_VERIFY_KEY_PATH: Optional[str] = "keys/ledger_ed25519_public.pem"

    model_config = SettingsConfigDict(
        env_file=(str(DOTENV_PATH), ".env"),
        case_sensitive=True,
        extra="ignore",
        env_file_encoding="utf-8"
    )

    @model_validator(mode="after")
    def resolve_paths(self):
        """Ensures relative paths resolve deterministically against PROJECT_ROOT and enforces production guardrails."""
        # Production Safety Guardrail: Never permit auth bypass in production
        if self.ENVIRONMENT.lower() == "production":
            self.DEV_AUTH_BYPASS = False
            if self.CAC_ADMIN_TOKEN in ("admin-token-cac-2026", None):
                raise ValueError("Insecure or missing CAC_ADMIN_TOKEN cannot be used in production environment.")

        # Resolve SQLite relative paths to canonical project root
        if self.DATABASE_URL.startswith("sqlite:///./"):
            rel_file = self.DATABASE_URL.replace("sqlite:///./", "")
            self.DATABASE_URL = f"sqlite:///{(PROJECT_ROOT / rel_file).resolve().as_posix()}"
        elif self.DATABASE_URL == "sqlite:///cac_grc.db":
            self.DATABASE_URL = f"sqlite:///{(PROJECT_ROOT / 'cac_grc.db').resolve().as_posix()}"

        # Resolve ledger key paths
        if self.LEDGER_SIGNING_KEY_PATH and not Path(self.LEDGER_SIGNING_KEY_PATH).is_absolute():
            cand = PROJECT_ROOT / self.LEDGER_SIGNING_KEY_PATH
            if cand.exists():
                self.LEDGER_SIGNING_KEY_PATH = str(cand.resolve())

        if self.LEDGER_VERIFY_KEY_PATH and not Path(self.LEDGER_VERIFY_KEY_PATH).is_absolute():
            cand = PROJECT_ROOT / self.LEDGER_VERIFY_KEY_PATH
            if cand.exists():
                self.LEDGER_VERIFY_KEY_PATH = str(cand.resolve())

        # Resolve SSH known hosts file
        if self.SSH_KNOWN_HOSTS_FILE and not Path(self.SSH_KNOWN_HOSTS_FILE).is_absolute():
            cand = PROJECT_ROOT / self.SSH_KNOWN_HOSTS_FILE
            if cand.exists():
                self.SSH_KNOWN_HOSTS_FILE = str(cand.resolve())

        return self


settings = Settings()
