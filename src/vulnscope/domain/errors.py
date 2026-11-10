"""Domain errors. Adapters translate these into transport-level responses."""


class DomainError(Exception):
    """Base class for every expected, business-level error."""


class ValidationError(DomainError):
    pass


class NotFoundError(DomainError):
    pass


class AuthError(DomainError):
    pass


class DuplicateVulnerabilityError(DomainError):
    """An identical vulnerability record already exists."""

    def __init__(self, existing_id: int):
        super().__init__("An identical vulnerability already exists")
        self.existing_id = existing_id


class ArchiveError(DomainError):
    """The uploaded archive is invalid, unsupported or unsafe."""


class AIUnavailableError(DomainError):
    """The external AI provider could not answer."""


class RateLimitedError(DomainError):
    """Too many attempts (e.g. account temporarily locked)."""
