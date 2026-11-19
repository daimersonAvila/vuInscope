"""Composition root: the only place where adapters are wired to ports."""
from __future__ import annotations

from dataclasses import dataclass

from .adapters.outbound.ai_http import OpenAICompatibleClient
from .adapters.outbound.archive_reader import ArchiveLimits, SafeArchiveReader
from .adapters.outbound.auth_adapters import ConfigAuthenticator, JwtTokenService
from .adapters.outbound.sqlite_repo import SqliteStore
from .application.use_cases import AIAdvisor, AuthService, LifecycleService, RegistryService, ScanService
from .config import Settings


@dataclass
class Container:
    settings: Settings
    registry: RegistryService
    scans: ScanService
    advisor: AIAdvisor
    lifecycle: LifecycleService
    auth: AuthService


def build_container(settings: Settings, ai_client=None) -> Container:
    store = SqliteStore(settings.db_path)
    primary = ai_client
    if primary is None and settings.ai_enabled:
        primary = OpenAICompatibleClient(settings.ai_url, settings.ai_model, settings.ai_api_key, settings.ai_timeout,
                                         name="pollinations-public-ai")
    return Container(
        settings=settings,
        registry=RegistryService(store, store),
        scans=ScanService(SafeArchiveReader(ArchiveLimits(max_total_bytes=settings.max_upload_mb * 4_000_000))),
        advisor=AIAdvisor(primary, None),
        lifecycle=LifecycleService(store),
        auth=AuthService(ConfigAuthenticator(settings.admin_username, settings.admin_password_hash),
                         JwtTokenService(settings.secret_key, settings.token_ttl)),
    )
