"""Checks on a rule definition that need the database.

A regex is only ever evaluated by PostgreSQL, under a statement timeout. Before
a rule with one is saved or tested, PostgreSQL must accept the pattern, and it
must finish quickly against a long, adversarial input. (Backreferences, the
usual source of catastrophic backtracking, are already rejected by the validator.)
"""

import time

import asyncpg

from models.rule_definitions import InvalidDefinition, regex_patterns

REGEX_CHECK_TIMEOUT = "1s"
# Seconds a probe may take beyond an ordinary query's round trip.
REGEX_PROBE_BUDGET = 0.5
_PROBE_SQL = "SELECT (repeat('a', 50000) || '!') ~* $1"


async def check_regexes(conn, definition: dict) -> None:
    for path, pattern in regex_patterns(definition):
        try:
            async with conn.transaction():
                await conn.execute(f"SET LOCAL statement_timeout = '{REGEX_CHECK_TIMEOUT}'")
                started = time.perf_counter()
                await conn.fetchval("SELECT '' ~* $1", pattern)
                round_trip = time.perf_counter() - started

                started = time.perf_counter()
                await conn.fetchval(_PROBE_SQL, pattern)
                probe = time.perf_counter() - started
        except asyncpg.InvalidRegularExpressionError:
            raise InvalidDefinition(f"{path}: not a regular expression PostgreSQL accepts") from None
        except asyncpg.QueryCanceledError:
            raise InvalidDefinition(f"{path}: too slow to evaluate safely; simplify the pattern") from None
        if probe - round_trip > REGEX_PROBE_BUDGET:
            raise InvalidDefinition(f"{path}: too slow to evaluate safely; simplify the pattern")
