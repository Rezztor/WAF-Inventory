"""Credentials encrypted in the database under a master key that lives outside it.

The key file (default /run/secrets/master_key, a Docker secret) holds one Fernet key per line. The first line
encrypts and every line decrypts, so a new key can be put first while old secrets still read.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .auth import _now
from .models import Secret, SourceConfig


class VaultError(RuntimeError):
    pass


def key_file() -> Path:
    return Path(os.environ.get("WAF_INV_MASTER_KEY_FILE", "/run/secrets/master_key"))


def _fernet() -> MultiFernet:
    try:
        keys = [k.strip() for k in key_file().read_text().splitlines() if k.strip()]
        return MultiFernet([Fernet(k) for k in keys])
    except (OSError, ValueError) as e:
        raise VaultError(f"master key unreadable at {key_file()} ({type(e).__name__}); "
                         "mount it as the master_key Docker secret or set WAF_INV_MASTER_KEY_FILE") from None


def put(sc: SourceConfig, kind: str, value: str, meta: dict | None = None) -> None:
    sec = next((x for x in sc.secrets if x.kind == kind), None)
    if sec is None:
        sec = Secret(kind=kind)
        sc.secrets.append(sec)
    sec.token, sec.meta, sec.updated = _fernet().encrypt(value.encode()).decode(), meta or {}, _now()


def get(sc: SourceConfig, kind: str) -> str | None:
    sec = next((x for x in sc.secrets if x.kind == kind), None)
    if sec is None:
        return None
    try:
        return _fernet().decrypt(sec.token.encode()).decode()
    except InvalidToken:
        raise VaultError(f"the {kind} of {sc.name} was encrypted with a different master key; enter it again") from None

