"""
store.py -- where a running job's status lives.

WHY THIS FILE EXISTS
--------------------
The API process and the worker process are different processes (with Celery,
sometimes different machines). The API needs to answer "how far is scan 123?"
so the status must live somewhere BOTH can see: Redis.

For students without Redis installed we also provide an in-memory store with
exactly the same methods. The rest of the code does not care which one it
gets, which is the "program to an interface" idea in practice.
"""

import json               # job records are stored as JSON text
import threading          # a lock protects the dict from concurrent threads
import time               # for expiry timestamps

import redis              # the Redis client (works with Memurai on Windows too)

from .settings import REDIS_URL, JOB_TTL_SECONDS


class MemoryStore:
    """A tiny Redis look-alike backed by a Python dict. Dies with the process."""

    def __init__(self) -> None:
        self._data = {}                     # key -> (json_string, expires_at_epoch)
        self._lock = threading.Lock()       # thread-safety: FastAPI and the worker share this dict

    def set(self, key: str, value: dict, ttl: int = JOB_TTL_SECONDS) -> None:
        """Store a whole record."""
        with self._lock:                                        # only one thread at a time
            self._data[key] = (json.dumps(value), time.time() + ttl)   # serialise + expiry time

    def get(self, key: str):
        """Return the record, or None when missing/expired."""
        with self._lock:
            item = self._data.get(key)                          # tuple or None
            if item is None:
                return None
            payload, expires_at = item
            if time.time() > expires_at:                        # lazy expiry, like Redis TTL
                del self._data[key]
                return None
            return json.loads(payload)                          # back to a dict

    def update(self, key: str, patch: dict, ttl: int = JOB_TTL_SECONDS) -> None:
        """Merge new fields into an existing record (used for progress updates)."""
        with self._lock:
            item = self._data.get(key)
            current = json.loads(item[0]) if item else {}       # existing record or empty
            current.update(patch)                               # apply the changes
            self._data[key] = (json.dumps(current), time.time() + ttl)   # store + refresh TTL


class RedisStore:
    """The same three methods, backed by Redis."""

    def __init__(self, url: str) -> None:
        self._client = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=1)

    def set(self, key: str, value: dict, ttl: int = JOB_TTL_SECONDS) -> None:
        self._client.setex(key, ttl, json.dumps(value))         # SETEX = set + expire in one command

    def get(self, key: str):
        raw = self._client.get(key)                             # None when the key expired
        return json.loads(raw) if raw else None

    def update(self, key: str, patch: dict, ttl: int = JOB_TTL_SECONDS) -> None:
        current = self.get(key) or {}                           # read-modify-write
        current.update(patch)
        self.set(key, current, ttl)                             # rewrite with a fresh TTL


# ---------------------------------------------------------------------------
# One-time detection: is Redis actually reachable?
# Doing a TCP ping on every request would add latency, so we cache the answer.
# ---------------------------------------------------------------------------
_redis_available = None     # None = not checked yet, True/False = cached answer


def redis_available() -> bool:
    """Return True when a Redis server answers our ping."""

    global _redis_available              # we are modifying the module-level variable
    if _redis_available is not None:     # already answered
        return _redis_available

    try:
        client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=0.5, socket_timeout=0.5)
        client.ping()                    # the cheapest possible round-trip
        _redis_available = True
    except Exception:                    # connection refused, timeout, no redis module...
        _redis_available = False
    return _redis_available


_store = None   # the singleton instance


def get_store():
    """Return the one store instance the whole process should use."""

    global _store
    if _store is None:                                   # first call -> build it
        _store = RedisStore(REDIS_URL) if redis_available() else MemoryStore()
    return _store
