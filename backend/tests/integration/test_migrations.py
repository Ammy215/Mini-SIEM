"""The migration runner against real Postgres.

Every DB test runs in its own throwaway schema (via search_path), so the
runner builds a complete database from scratch without touching the tables
the rest of the suite uses."""

import uuid

import asyncpg
import pytest
import pytest_asyncio

from migrations import (
    MigrationError, apply_all, assert_schema_current, current_version, discover, expected_version,
)

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest_asyncio.fixture(loop_scope="session")
async def scratch_conn(pool):
    """A connection inside one transaction whose search_path points at a brand
    new schema; the schema and everything in it are rolled back afterwards.

    The single transaction matters: the app reaches Neon through PgBouncer in
    transaction mode, where a plain session-level SET can land on a different
    server connection than the statements after it — and those statements
    would then run against the real tables. A transaction stays on one server
    connection, and SET LOCAL lives exactly as long as it. The runner's own
    transactions nest inside as savepoints."""
    schema = f"test_migrations_{uuid.uuid4().hex[:12]}"
    async with pool.acquire() as c:
        tr = c.transaction()
        await tr.start()
        try:
            await c.execute(f'CREATE SCHEMA "{schema}"')
            await c.execute(f'SET LOCAL search_path TO "{schema}"')
            assert await c.fetchval("SELECT current_schema()") == schema
            yield c
        finally:
            await tr.rollback()


def _write(directory, name, content):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(content, encoding="utf-8")


async def _table_exists(conn, name):
    return await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1)",
        name,
    )


async def test_fresh_database_is_built_and_rerunning_changes_nothing(scratch_conn):
    assert await current_version(scratch_conn) == 0
    with pytest.raises(MigrationError, match="Run: python scripts/migrate.py"):
        await assert_schema_current(scratch_conn)

    applied = await apply_all(scratch_conn)
    assert [m.version for m in applied] == [m.version for m in discover()]
    assert await current_version(scratch_conn) == expected_version()
    await assert_schema_current(scratch_conn)
    for table in ("users", "events", "rules", "alerts", "incidents", "schema_migrations"):
        assert await _table_exists(scratch_conn, table), table

    assert await apply_all(scratch_conn) == []
    assert await current_version(scratch_conn) == expected_version()


async def test_existing_rows_survive_sql_and_python_migrations(scratch_conn, tmp_path):
    # A v1 database that already holds data, like the live Neon one.
    await apply_all(scratch_conn, migrations_dir=tmp_path / "none")
    event_id = await scratch_conn.fetchval(
        "INSERT INTO events (event_time, source_type, raw_message) VALUES (now(), 'ssh', 'kept') RETURNING id"
    )

    migrations_dir = tmp_path / "migrations"
    _write(migrations_dir, "0001_add_host.sql", "ALTER TABLE events ADD COLUMN IF NOT EXISTS host TEXT;")
    _write(
        migrations_dir, "0002_backfill_host.py",
        "async def up(conn):\n    await conn.execute(\"UPDATE events SET host = 'backfilled' WHERE host IS NULL\")\n",
    )

    applied = await apply_all(scratch_conn, migrations_dir=migrations_dir)
    assert [m.label for m in applied] == ["0001_add_host", "0002_backfill_host"]

    row = await scratch_conn.fetchrow("SELECT raw_message, host FROM events WHERE id = $1", event_id)
    assert row["raw_message"] == "kept"
    assert row["host"] == "backfilled"
    assert await current_version(scratch_conn) == 2


async def test_a_failing_migration_rolls_back_and_is_not_recorded(scratch_conn, tmp_path):
    migrations_dir = tmp_path / "migrations"
    _write(migrations_dir, "0001_ok.sql", "CREATE TABLE mig_ok (id INT);")
    _write(migrations_dir, "0002_breaks.sql", "CREATE TABLE mig_half_done (id INT);\nSELECT 1 / 0;")

    with pytest.raises(asyncpg.DivisionByZeroError):
        await apply_all(scratch_conn, migrations_dir=migrations_dir)

    assert await _table_exists(scratch_conn, "mig_ok")
    assert not await _table_exists(scratch_conn, "mig_half_done")
    assert await current_version(scratch_conn) == 1


async def test_an_edited_migration_stops_the_run_before_anything_new_applies(scratch_conn, tmp_path):
    migrations_dir = tmp_path / "migrations"
    _write(migrations_dir, "0001_probe.sql", "CREATE TABLE mig_probe (id INT);")
    await apply_all(scratch_conn, migrations_dir=migrations_dir)

    _write(migrations_dir, "0001_probe.sql", "CREATE TABLE mig_probe (id BIGINT);")
    _write(migrations_dir, "0002_next.sql", "CREATE TABLE mig_next (id INT);")

    with pytest.raises(MigrationError, match="checksum mismatch"):
        await apply_all(scratch_conn, migrations_dir=migrations_dir)
    assert not await _table_exists(scratch_conn, "mig_next")


async def test_code_older_than_the_database_is_refused(scratch_conn, tmp_path):
    migrations_dir = tmp_path / "migrations"
    _write(migrations_dir, "0001_one.sql", "CREATE TABLE mig_one (id INT);")
    _write(migrations_dir, "0002_two.sql", "CREATE TABLE mig_two (id INT);")
    await apply_all(scratch_conn, migrations_dir=migrations_dir)

    (migrations_dir / "0002_two.sql").unlink()
    with pytest.raises(MigrationError, match="doesn't have"):
        await apply_all(scratch_conn, migrations_dir=migrations_dir)
    with pytest.raises(MigrationError, match="newer than this code"):
        await assert_schema_current(scratch_conn, migrations_dir=migrations_dir)


async def test_windows_line_endings_do_not_change_the_checksum(tmp_path):
    (tmp_path / "lf").mkdir()
    (tmp_path / "crlf").mkdir()
    (tmp_path / "lf" / "0001_x.sql").write_bytes(b"CREATE TABLE x (id INT);\nSELECT 1;\n")
    (tmp_path / "crlf" / "0001_x.sql").write_bytes(b"CREATE TABLE x (id INT);\r\nSELECT 1;\r\n")
    assert discover(tmp_path / "lf")[0].checksum == discover(tmp_path / "crlf")[0].checksum


async def test_badly_named_and_duplicate_migrations_are_rejected(tmp_path):
    bad = tmp_path / "bad"
    _write(bad, "add_column.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="must be named"):
        discover(bad)

    dupes = tmp_path / "dupes"
    _write(dupes, "0003_first.sql", "SELECT 1;")
    _write(dupes, "0003_second.py", "async def up(conn):\n    pass\n")
    with pytest.raises(MigrationError, match="duplicate migration version 0003"):
        discover(dupes)


async def test_the_shipped_migrations_directory_is_valid():
    migrations = discover()
    assert migrations, "backend/sql/migrations should contain at least 0001"
    assert [m.version for m in migrations] == list(range(1, len(migrations) + 1)), "versions must have no gaps"
