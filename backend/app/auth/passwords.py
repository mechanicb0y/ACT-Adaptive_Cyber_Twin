"""Password hashing - bcrypt, nothing else.

``bcrypt`` silently truncates anything past 72 bytes, which is a well-known
footgun, so :func:`hash_password` rejects longer inputs rather than hashing a
prefix. Verification is constant-time (bcrypt's own ``checkpw``).
"""

from __future__ import annotations

import bcrypt

MAX_PASSWORD_BYTES = 72
_DEFAULT_ROUNDS = 12


class PasswordTooLong(ValueError):
    pass


def hash_password(plain: str, *, rounds: int = _DEFAULT_ROUNDS) -> str:
    raw = plain.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise PasswordTooLong(
            f"password must be at most {MAX_PASSWORD_BYTES} bytes"
        )
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds)).decode("ascii")


def verify_password(plain: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    raw = plain.encode("utf-8")[:MAX_PASSWORD_BYTES]
    try:
        return bcrypt.checkpw(raw, hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False
