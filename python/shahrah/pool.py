"""Connecting.

shahrah pools connections to the shards itself, so an application pool in front
of it is about client-side concurrency, not about protecting the database.
"""

from __future__ import annotations

import asyncpg


async def connect(dsn: str, **kwargs) -> asyncpg.Connection:
    """One connection to shahrah."""
    return await asyncpg.connect(dsn, **kwargs)


async def pool(dsn: str, *, min_size: int = 1, max_size: int = 10, **kwargs) -> asyncpg.Pool:
    """A client-side pool.

    `statement_cache_size` is left alone: shahrah translates prepared-statement
    names per backend connection, which is the thing pgbouncer cannot do, so
    asyncpg's own caching is safe here.
    """
    return await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size, **kwargs)
