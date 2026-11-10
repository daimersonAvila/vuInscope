"""Ports: the interfaces the application core needs from the outside world."""
from __future__ import annotations

from typing import List, Optional, Protocol, Tuple

from ..domain.models import Vulnerability
from ..domain.scanner import ArchiveContents


class VulnerabilityRepository(Protocol):
    def add(self, v: Vulnerability) -> Vulnerability: ...          # raises DuplicateVulnerabilityError
    def get(self, vuln_id: int) -> Optional[Vulnerability]: ...
    def list(self) -> List[Vulnerability]: ...
    def update(self, v: Vulnerability) -> Optional[Vulnerability]: ...  # raises DuplicateVulnerabilityError
    def delete(self, vuln_id: int) -> bool: ...


class StateHistoryRepository(Protocol):
    def record(self, vuln_id: int, state: str) -> None: ...
    def sequences(self) -> List[List[str]]: ...


class ArchiveReader(Protocol):
    def read(self, data: bytes) -> ArchiveContents: ...           # raises ArchiveError


class AIClient(Protocol):
    name: str
    def complete(self, system: str, user: str) -> str: ...        # raises AIUnavailableError


class Authenticator(Protocol):
    def verify(self, username: str, password: str) -> bool: ...


class TokenService(Protocol):
    def issue(self, username: str) -> Tuple[str, int]: ...         # (token, expires_in_seconds)
    def verify(self, token: str) -> str: ...                       # returns username, raises AuthError
