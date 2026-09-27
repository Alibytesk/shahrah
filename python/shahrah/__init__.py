"""Talk to a shahrah proxy from Python.

shahrah speaks the PostgreSQL wire protocol, so asyncpg reaches it with no help
from this package. What is here is the part that is shahrah's own: the routing
hints, and the console that answers where a key lives.
"""

from .hints import by_key, on_shard
from .pool import connect, pool
from .console import ask, fleet, health, traffic, where_is

__all__ = [
    "ask",
    "by_key",
    "connect",
    "fleet",
    "health",
    "on_shard",
    "pool",
    "traffic",
    "where_is",
]
