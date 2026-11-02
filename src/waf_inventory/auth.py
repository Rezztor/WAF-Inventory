"""Local sign-in: Argon2id password hashes, server-side sessions with CSRF tokens, back-off after failed logins."""
from __future__ import annotations

import hashlib
import math
import secrets
import time
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy.orm import Session

from .models import LoginSession, User, now

COOKIE = "waf_session"
IDLE, ABSOLUTE = timedelta(minutes=30), timedelta(hours=12)
MIN_PASSWORD = 12
ph = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)  # OWASP minimum for Argon2id
_DUMMY = ph.hash(secrets.token_hex())  # checked for unknown users so response time does not reveal which names exist


def _now() -> datetime:
    return now().replace(tzinfo=None)  # SQLite hands datetimes back naive


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def has_users(s: Session) -> bool:
    return s.query(User.id).first() is not None


def set_password(s: Session, username: str, password: str) -> User:
    """Create the user or replace its password; signs it out everywhere."""
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"password must be at least {MIN_PASSWORD} characters")
    user = s.query(User).filter_by(username=username).one_or_none()
    if user is None:
        user = User(username=username, password_hash="")
        s.add(user)
    else:
        s.query(LoginSession).filter_by(user_id=user.id).delete()
    user.password_hash = ph.hash(password)
    s.commit()
    return user


def authenticate(s: Session, username: str, password: str) -> User | None:
    user = s.query(User).filter_by(username=username).one_or_none()
    try:
        ph.verify(user.password_hash if user else _DUMMY, password)
    except (VerificationError, InvalidHashError):
        return None
    if user and ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(password)
    return user


def start_session(s: Session, user: User, ip: str | None, user_agent: str | None) -> str:
    token, t = secrets.token_urlsafe(32), _now()
    s.add(LoginSession(id=_h(token), user_id=user.id, csrf=secrets.token_urlsafe(32), created=t, last_seen=t,
                       ip=ip, user_agent=(user_agent or "")[:200]))
    user.last_login = t
    s.commit()
    return token


def load_session(s: Session, token: str | None) -> LoginSession | None:
    ls = s.get(LoginSession, _h(token)) if token else None
    if ls is None:
        return None
    t = _now()
    if t - ls.last_seen > IDLE or t - ls.created > ABSOLUTE:
        s.delete(ls)
        s.commit()
        return None
    ls.last_seen = t
    s.commit()
    return ls


def end_session(s: Session, token: str | None) -> None:
    if token:
        s.query(LoginSession).filter_by(id=_h(token)).delete()
        s.commit()


# ponytail: in-memory counters, fine for one process; move to the database if the app ever runs as several.
_fails: dict[str, tuple[int, float]] = {}  # key -> (failures, blocked until)


def wait_seconds(*keys: str) -> int:
    """Seconds left before these keys (user name, client IP) may try again."""
    left = max((_fails[k][1] - time.monotonic() for k in keys if k in _fails), default=0)
    return math.ceil(left) if left > 0 else 0


def record_attempt(ok: bool, *keys: str) -> None:
    """From the 5th failure on, block for 30 s, doubling each time, capped at 15 minutes. Never a permanent lockout."""
    for k in keys:
        if ok:
            _fails.pop(k, None)
            continue
        n = _fails.get(k, (0, 0))[0] + 1
        _fails[k] = (n, time.monotonic() + (min(900, 30 * 2 ** (n - 5)) if n >= 5 else 0))
