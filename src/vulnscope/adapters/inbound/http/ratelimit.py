"""Small in-process sliding-window rate limiter.
NOTE: per-process state. Behind several gunicorn workers use a shared store (Redis) or the proxy's limiter."""
import threading
import time
from collections import deque
from typing import Deque, Dict, Tuple


class RateLimiter:
    def __init__(self):
        self._hits: Dict[Tuple[str, str], Deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, bucket: str, client: str, limit: int, window: int) -> Tuple[bool, int]:
        now = time.monotonic()
        key = (bucket, client)
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(window - (now - q[0])))
            q.append(now)
            if len(self._hits) > 20000:  # bound memory
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > window][:5000]:
                    self._hits.pop(k, None)
            return True, 0
