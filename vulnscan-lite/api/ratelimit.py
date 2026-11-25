"""
ratelimit.py -- stop one visitor from hammering the scanner (Week 4).

ALGORITHM: sliding window
-------------------------
We keep the timestamps of the visitor's recent scans in a deque (a list with
fast pops from the left). On every request:

  1. drop timestamps older than the window (e.g. 1 hour),
  2. if the deque already holds `limit` entries -> reject,
  3. otherwise append "now" and allow.

Why not a fixed counter? Because a fixed counter lets someone send 30 scans
at 12:59 and 30 more at 13:01. A sliding window cannot be gamed that way.

For production across multiple servers you would store the deque in Redis;
in-process memory is correct for a single-server deployment.
"""

import threading                     # the dict is shared between request threads
import time                          # timestamps
from collections import defaultdict, deque   # per-key list of hits

from .errors import ApiError          # to return a clean 429 response

from .settings import RATE_LIMIT, RATE_WINDOW_SECONDS


class SlidingWindowLimiter:
    """A thread-safe sliding-window rate limiter."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit                                    # max requests per window
        self.window = window_seconds                          # window length in seconds
        self._hits = defaultdict(deque)                       # key -> deque[float]
        self._lock = threading.Lock()                         # one writer at a time

    def check(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""

        now = time.time()                                     # current epoch seconds
        with self._lock:                                      # critical section
            hits = self._hits[key]                            # this visitor's history
            while hits and now - hits[0] > self.window:       # remove expired entries
                hits.popleft()
            if len(hits) >= self.limit:                       # quota exhausted
                retry_after = int(self.window - (now - hits[0])) + 1
                return False, retry_after
            hits.append(now)                                  # count this request
            return True, 0


# One limiter for the whole process, configured from settings.py.
_limiter = SlidingWindowLimiter(RATE_LIMIT, RATE_WINDOW_SECONDS)


def check_or_raise(key: str) -> None:
    """Raise HTTP 429 when the key is over the limit."""

    allowed, retry_after = _limiter.check(key)
    if not allowed:
        raise ApiError(
            429,
            (
                f"Rate limit reached: {RATE_LIMIT} scans per hour. "
                f"Try again in {retry_after} seconds."
            ),
            headers={"Retry-After": str(retry_after)},       # standard header for 429
        )
