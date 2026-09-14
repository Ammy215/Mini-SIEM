"""Versioned, forward-only schema migrations.

sql/schema.sql is the frozen v1 baseline and always runs first (it is fully
idempotent). Every later schema change is a numbered file in sql/migrations/:

    NNNN_name.sql   plain SQL
    NNNN_name.py    a data migration exposing `async def up(conn)`

Each file is applied exactly once, in version order, inside its own
transaction, and recorded in schema_migrations with a checksum. An applied
file that is later edited stops the run instead of silently diverging — the
fix is always a new migration, never an edit.

Concurrency: two runners (say, two deploys starting at once) are serialised
with a *transaction-level* advisory lock taken inside each migration's
transaction. Not a session-level lock: the app reaches Neon through PgBouncer
in transaction mode, which can run a session lock and its unlock on different
server connections. A transaction always stays on one.

A .sql file whose first line is `-- migrate:no-transaction` runs outside a
transaction (needed for CREATE INDEX CONCURRENTLY). Postgres only allows that
for a single statement, so such a file must contain exactly one — and, having
no transaction to lock in, it relies on the schema_migrations primary key to
make a concurrent duplicate fail loudly. Write those statements idempotently
(`IF NOT EXISTS`).
"""

import hashlib
import importlib.util
import inspect
import re
from dataclasses import dataclass
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
BASELINE_PATH = BACKEND_DIR / "sql" / "schema.sql"
MIGRATIONS_DIR = BACKEND_DIR / "sql" / "migrations"

# Any constant works, as long as every migrate run uses the same one.
_ADVISORY_LOCK_KEY = 7_420_311_001

_FILENAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.(sql|py)$")
_NO_TRANSACTION_HEADER = "-- migrate:no-transaction"

_BOOTSTRAP_SQL = """
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INT PRIMARY KEY,
      name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
"""


class MigrationError(Exception):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    kind: str  # "sql" | "py"

    @property
    def label(self) -> str:
        return f"{self.version:04d}_{self.name}"

    @property
    def checksum(self) -> str:
        # Line endings are normalised first: git checks this file out with CRLF
        # on Windows and LF on Render/CI, and a database migrated from one must
        # not look tampered with when the other runs migrate.py against it.
        content = self.path.read_bytes().replace(b"\r\n", b"\n")
        return hashlib.sha256(content).hexdigest()


def discover(migrations_dir: Path = MIGRATIONS_DIR) -> list[Migration]:
    if not migrations_dir.is_dir():
        return []

    found: dict[int, Migration] = {}
    for path in sorted(migrations_dir.iterdir()):
        if path.is_dir() or path.name.startswith((".", "_")):
            continue  # __pycache__, .gitkeep
        match = _FILENAME_RE.match(path.name)
        if not match:
            raise MigrationError(f"{path.name}: migration files must be named NNNN_name.sql or NNNN_name.py")
        version = int(match.group(1))
        if version in found:
            raise MigrationError(
                f"duplicate migration version {version:04d}: {found[version].path.name} and {path.name}"
            )
        found[version] = Migration(version, match.group(2), path, match.group(3))

    return [found[v] for v in sorted(found)]


def expected_version(migrations_dir: Path = MIGRATIONS_DIR) -> int:
    migrations = discover(migrations_dir)
    return migrations[-1].version if migrations else 0


async def current_version(conn) -> int:
    has_table = await conn.fetchval("SELECT to_regclass('schema_migrations') IS NOT NULL")
    if not has_table:
        return 0
    return await conn.fetchval("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")


async def apply_all(
    conn, migrations_dir: Path = MIGRATIONS_DIR, baseline_path: Path = BASELINE_PATH
) -> list[Migration]:
    """Brings the database up to date. Returns the migrations applied by this call."""
    migrations = discover(migrations_dir)

    async with conn.transaction():
        await _lock(conn)
        await conn.execute(baseline_path.read_text(encoding="utf-8"))
        await conn.execute(_BOOTSTRAP_SQL)
        # Check the whole recorded history before running anything new, so a
        # mismatch never gets a fresh migration stacked on top of it.
        _verify_history(migrations, await _applied_checksums(conn))

    newly_applied = []
    for migration in migrations:
        if await _apply_one(conn, migration):
            newly_applied.append(migration)
    return newly_applied


async def assert_schema_current(conn, migrations_dir: Path = MIGRATIONS_DIR) -> None:
    """Refuses to run against a database whose schema doesn't match this code."""
    expected = expected_version(migrations_dir)
    current = await current_version(conn)
    if current < expected:
        raise MigrationError(
            f"database schema is at version {current}, but this code needs {expected}. "
            "Run: python scripts/migrate.py"
        )
    if current > expected:
        raise MigrationError(
            f"database schema is at version {current}, newer than this code ({expected}). "
            "Update the code before starting it against this database."
        )


def _verify_history(migrations: list[Migration], applied: dict[int, str]) -> None:
    for migration in migrations:
        if migration.version in applied and applied[migration.version] != migration.checksum:
            raise MigrationError(
                f"migration {migration.label} was edited after it was applied (checksum mismatch). "
                "Never change an applied migration — add a new one instead."
            )
    unknown = sorted(set(applied) - {m.version for m in migrations})
    if unknown:
        raise MigrationError(
            f"the database has migrations this code doesn't have: {unknown}. "
            "Is this checkout older than the database?"
        )


async def _apply_one(conn, migration: Migration) -> bool:
    """Applies one migration unless it is already recorded. Returns whether
    this call applied it."""
    sql = migration.path.read_text(encoding="utf-8") if migration.kind == "sql" else None

    if sql is not None and sql.lstrip().startswith(_NO_TRANSACTION_HEADER):
        if await _is_applied(conn, migration.version):
            return False
        await conn.execute(sql)
        await _record(conn, migration)
        return True

    async with conn.transaction():
        await _lock(conn)
        # Re-checked under the lock: a concurrent runner may have applied it
        # while this one was waiting.
        if await _is_applied(conn, migration.version):
            return False
        if sql is not None:
            await conn.execute(sql)
        else:
            await _load_up(migration)(conn)
        await _record(conn, migration)
    return True


async def _lock(conn) -> None:
    # Released automatically when the surrounding transaction ends.
    await conn.execute("SELECT pg_advisory_xact_lock($1::bigint)", _ADVISORY_LOCK_KEY)


async def _applied_checksums(conn) -> dict[int, str]:
    rows = await conn.fetch("SELECT version, checksum FROM schema_migrations")
    return {row["version"]: row["checksum"] for row in rows}


async def _is_applied(conn, version: int) -> bool:
    return await conn.fetchval("SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version)


def _load_up(migration: Migration):
    spec = importlib.util.spec_from_file_location(f"_migration_{migration.label}", migration.path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    up = getattr(module, "up", None)
    if up is None or not inspect.iscoroutinefunction(up):
        raise MigrationError(f"{migration.path.name}: must define `async def up(conn)`")
    return up


async def _record(conn, migration: Migration) -> None:
    await conn.execute(
        "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
        migration.version, migration.name, migration.checksum,
    )
