"""
auth.py -- minimal email + password accounts (Week 4: scan history).

WHY NOT USE A LIBRARY?
----------------------
For a portfolio project, a full auth framework adds a lot of magic. This file
shows the three ideas you actually need to understand:

  1. never store a password -- store a slow hash of it (PBKDF2 here),
  2. compare hashes in constant time (hmac.compare_digest),
  3. give the browser an opaque random token, and look that token up.

If you later need OAuth, 2FA or refresh tokens, replace this file with a
library -- the rest of the app only calls optional_user() / require_user().
"""

import hashlib                 # PBKDF2 lives here
import hmac                    # compare_digest avoids timing attacks
import re                      # email validation
import secrets                 # cryptographically secure random tokens
import sqlite3                 # to catch UNIQUE violations
from datetime import datetime, timezone

from flask import request      # reads the Authorization header

from .errors import ApiError
from .history import db

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")   # something@something.tld
PBKDF2_ROUNDS = 200_000        # ~0.1s per hash: fast for us, slow for a brute-forcer


def _hash_password(password: str, salt_hex: str) -> str:
    """Derive a hex hash from a password + salt."""

    salt = bytes.fromhex(salt_hex)                              # salt is stored as hex text
    digest = hashlib.pbkdf2_hmac(
        "sha256",                                               # hash function
        password.encode("utf-8"),                               # password as bytes
        salt,                                                   # per-user random salt
        PBKDF2_ROUNDS,                                          # work factor
    )
    return digest.hex()                                         # store as text


def _create_session(user_id: int, email: str) -> dict:
    """Create a login token and return it together with the user info."""

    token = secrets.token_urlsafe(32)                           # 256 bits of randomness
    now = datetime.now(timezone.utc).isoformat()                # ISO timestamp
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, now),
        )
    return {"token": token, "user": {"id": user_id, "email": email}}   # the API response


def register(email: str, password: str) -> dict:
    """Create an account and log the user in immediately."""

    email = (email or "").strip().lower()                       # normalise before validating
    if not EMAIL_RE.match(email):
        raise ApiError(400, "Please enter a valid email address.")
    if len(password or "") < 8:
        raise ApiError(400, "The password must be at least 8 characters.")

    salt_hex = secrets.token_hex(16)                            # 16 random bytes -> 32 hex chars
    password_hash = _hash_password(password, salt_hex)          # never store the password itself
    now = datetime.now(timezone.utc).isoformat()

    try:
        with db() as conn:
            cursor = conn.execute(
                "INSERT INTO users (email, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (email, password_hash, salt_hex, now),
            )
            user_id = cursor.lastrowid                          # AUTOINCREMENT assigned this id
    except sqlite3.IntegrityError:                              # UNIQUE(email) was violated
        raise ApiError(409, "An account with that email already exists.")

    return _create_session(user_id, email)                      # auto-login after signup


def login(email: str, password: str) -> dict:
    """Check the password and create a new session token."""

    email = (email or "").strip().lower()
    with db() as conn:
        row = conn.execute(
            "SELECT id, email, password_hash, salt FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    # Same message for "no such user" and "wrong password": do not tell an
    # attacker which emails exist.
    if row is None:
        raise ApiError(401, "Email or password is incorrect.")

    candidate = _hash_password(password or "", row["salt"])      # hash the attempt with the stored salt
    if not hmac.compare_digest(candidate, row["password_hash"]):  # constant-time comparison
        raise ApiError(401, "Email or password is incorrect.")

    return _create_session(row["id"], row["email"])


def _bearer_token(authorization: str | None) -> str | None:
    """Extract the token from 'Authorization: Bearer <token>'."""

    if not authorization:
        return None
    parts = authorization.split()                                # ["Bearer", "abc123"]
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def user_from_token(token: str | None):
    """Look up the user that owns a session token."""

    if not token:
        return None
    with db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.email
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    return dict(row) if row else None                            # None = invalid token


def optional_user():
    """Return the logged-in user, or None when no valid token was sent."""

    return user_from_token(_bearer_token(request.headers.get("Authorization")))


def require_user() -> dict:
    """Return the logged-in user, or raise 401."""

    user = optional_user()
    if user is None:
        raise ApiError(
            401,
            "Please log in first.",
            headers={"WWW-Authenticate": "Bearer"},              # correct HTTP semantics
        )
    return user
