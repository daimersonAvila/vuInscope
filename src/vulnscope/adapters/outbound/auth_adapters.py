"""Authentication adapters: hashed-password authenticator + JWT token service."""
from __future__ import annotations

import datetime as dt
import hmac
import time
import uuid
from typing import Dict, Tuple

import jwt
from werkzeug.security import check_password_hash, generate_password_hash

from ...domain.errors import AuthError, RateLimitedError

_DUMMY_HASH = generate_password_hash("dummy-password-for-timing-equalisation")


class ConfigAuthenticator:
    """Single admin account from configuration; only a salted hash is ever stored.
    Per-username lockout (in addition to the per-IP rate limit)."""

    def __init__(self, username: str, password_hash: str, max_failures: int = 5, lock_seconds: int = 300):
        self.username, self.password_hash = username, password_hash
        self.max_failures, self.lock_seconds = max_failures, lock_seconds
        self._fails: Dict[str, Tuple[int, float]] = {}

    def verify(self, username: str, password: str) -> bool:
        count, until = self._fails.get(username, (0, 0.0))
        if until > time.time():
            raise RateLimitedError("Too many failed attempts. Try again later.")
        known = hmac.compare_digest(username.encode(), self.username.encode())
        ok = check_password_hash(self.password_hash if known else _DUMMY_HASH, password) and known
        if ok:
            self._fails.pop(username, None)
            return True
        if len(self._fails) > 1000:
            self._fails.clear()
        count += 1
        self._fails[username] = (count, time.time() + self.lock_seconds if count >= self.max_failures else 0.0)
        return False


class JwtTokenService:
    ISS = "vulnscope"

    def __init__(self, secret: str, ttl_seconds: int = 3600):
        self.secret, self.ttl = secret, ttl_seconds

    def issue(self, username: str):
        now = dt.datetime.now(dt.timezone.utc)
        payload = {"sub": username, "iss": self.ISS, "iat": now, "nbf": now, "jti": uuid.uuid4().hex,
                   "exp": now + dt.timedelta(seconds=self.ttl)}
        return jwt.encode(payload, self.secret, algorithm="HS256"), self.ttl

    def verify(self, token: str) -> str:
        try:
            data = jwt.decode(token, self.secret, algorithms=["HS256"], issuer=self.ISS,
                              options={"require": ["exp", "iat", "sub", "iss"]})
        except jwt.ExpiredSignatureError:
            raise AuthError("Token expired")
        except jwt.InvalidTokenError:
            raise AuthError("Invalid token")
        return data["sub"]
