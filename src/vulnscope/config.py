"""Environment-driven configuration. Production refuses to boot with weak or missing secrets."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from typing import Tuple

from werkzeug.security import generate_password_hash


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    env: str = "development"
    secret_key: str = ""
    db_path: str = "instance/vulnscope.db"
    admin_username: str = "admin"
    admin_password_hash: str = ""
    ai_enabled: bool = True
    ai_url: str = "https://text.pollinations.ai/openai"
    ai_model: str = "openai"
    ai_api_key: str = ""
    ai_timeout: int = 45
    max_upload_mb: int = 25
    allowed_hosts: Tuple[str, ...] = ()
    trusted_proxies: int = 0
    https_only: bool = False
    rate_scale: float = 1.0
    token_ttl: int = 3600
    dev_password: str = field(default="", repr=False)

    @property
    def production(self) -> bool:
        return self.env == "production"

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get("APP_ENV", "development").lower()
        s = cls(
            env=env,
            secret_key=os.environ.get("SECRET_KEY", ""),
            db_path=os.environ.get("DATABASE_PATH", "instance/vulnscope.db"),
            admin_username=os.environ.get("ADMIN_USERNAME", "admin"),
            admin_password_hash=os.environ.get("ADMIN_PASSWORD_HASH", ""),
            ai_enabled=_bool("AI_ENABLED", True),
            ai_url=os.environ.get("AI_URL", "https://text.pollinations.ai/openai"),
            ai_model=os.environ.get("AI_MODEL", "openai"),
            ai_api_key=os.environ.get("AI_API_KEY", ""),
            max_upload_mb=int(os.environ.get("MAX_UPLOAD_MB", "25")),
            allowed_hosts=tuple(h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()),
            trusted_proxies=int(os.environ.get("TRUSTED_PROXIES", "0")),
            https_only=_bool("HTTPS_ONLY", env == "production"),
        )
        s.finalize()
        return s

    def finalize(self) -> None:
        if self.production:
            if len(self.secret_key) < 32:
                raise RuntimeError("SECRET_KEY must be set to a random string of at least 32 characters in production.")
            if not self.admin_password_hash:
                raise RuntimeError("ADMIN_PASSWORD_HASH must be set in production (see scripts/hash_password.py).")
            if not self.allowed_hosts:
                raise RuntimeError("ALLOWED_HOSTS must be set in production (comma-separated host names).")
        else:
            if not self.secret_key:
                self.secret_key = secrets.token_urlsafe(48)
            if not self.admin_password_hash:
                self.dev_password = "demo123"
                self.admin_password_hash = generate_password_hash(self.dev_password)
