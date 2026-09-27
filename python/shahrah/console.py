"""The console.

shahrah answers operator questions on a database called `shahrah`, over the same
wire protocol, and it answers them in the **simple** query protocol. asyncpg
prepares every statement it sends, so it cannot read rows from there -- it gets a
clear refusal rather than a hang. These helpers therefore drive `psql`, which is
what an operator has anyway.

For anything a program needs to read on a schedule, read `/metrics` instead: it is
the machine-readable surface and it carries the same facts.
"""

from __future__ import annotations

import shutil
import subprocess
from urllib.parse import urlsplit, urlunsplit

CONSOLE = "shahrah"
SEPARATOR = "\x1f"


def _to_console(dsn: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit(parts._replace(path=f"/{CONSOLE}"))


def ask(dsn: str, sql: str, timeout: float = 30.0) -> list[dict[str, str]]:
    """Run one console statement, once, and return its rows as dictionaries.

    Once matters: the console's verbs -- RELOCATE, DRAIN, REPAIR, REBALANCE --
    do something, and a helper that asked twice to learn the column names would
    do it twice.
    """
    if shutil.which("psql") is None:
        raise RuntimeError(
            "the shahrah console speaks the simple query protocol, so these helpers "
            "drive psql, and psql is not on PATH. Read /metrics instead, or install "
            "the postgresql client."
        )
    answered = subprocess.run(
        ["psql", _to_console(dsn), "--no-psqlrc", "--pset=footer=off",
         "-AF", SEPARATOR, "-c", sql],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if answered.returncode != 0:
        raise RuntimeError(f"the console refused {sql!r}: {answered.stderr.strip()}")
    lines = [line for line in answered.stdout.splitlines() if line.strip()]
    if not lines:
        return []
    names = lines[0].split(SEPARATOR)
    rows = []
    for line in lines[1:]:
        fields = line.split(SEPARATOR)
        if len(fields) != len(names):
            raise RuntimeError(
                f"the console answered {len(fields)} fields where it named "
                f"{len(names)} columns; refusing to guess which is which: {line!r}"
            )
        rows.append(dict(zip(names, fields)))
    return rows


def where_is(dsn: str, table: str, key: int | str) -> list[dict[str, str]]:
    """Which region a key lives in, and why shahrah thinks so."""
    return ask(dsn, f"WHERE IS {table} {key}")


def health(dsn: str) -> list[dict[str, str]]:
    """Every endpoint, its state, its role, and how far a replica is behind."""
    return ask(dsn, "SHOW HEALTH")


def traffic(dsn: str) -> list[dict[str, str]]:
    """Statements and errors counted per endpoint."""
    return ask(dsn, "SHOW TRAFFIC")


def fleet(dsn: str, subject: str = "HEALTH") -> list[dict[str, str]]:
    """The same question asked of every proxy in the group, not just this one."""
    return ask(dsn, f"SHOW FLEET {subject}")
