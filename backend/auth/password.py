import bcrypt

# Precomputed hash of a fixed dummy password, used when an email lookup
# misses so a nonexistent-email login takes roughly the same time as a
# real failed-password check (mitigates user-enumeration via timing).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing-parity", bcrypt.gensalt()).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def verify_dummy(password: str) -> None:
    bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH.encode("utf-8"))
