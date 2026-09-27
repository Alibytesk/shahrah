"""Routing hints.

A hint is a comment shahrah reads before it looks at the statement. Use one when
the statement does not carry the sharding key where shahrah can see it -- a join
that hides it, a function call, a statement written by an ORM you do not control.

    await connection.fetch(by_key(7, "select * from orders_view"))

Everything these two build is checked here rather than at the proxy: a hint that
shahrah would refuse is a runtime error in the middle of a request, and there is
no reason to find out then.
"""

MARKER = "shahrah:"
HIGHEST_SHARD = 65535


def by_key(key: int | str, sql: str) -> str:
    """Route this statement as if its key were `key`."""
    return f"/* {MARKER} key={_written(key)} */ {sql}"


def on_shard(shard: int, sql: str) -> str:
    """Send this statement to one shard by number, whatever it says."""
    if isinstance(shard, bool) or not isinstance(shard, int):
        raise TypeError(f"a shard number is an integer, not {type(shard).__name__}")
    if not 1 <= shard <= HIGHEST_SHARD:
        raise ValueError(f"a shard number is between 1 and {HIGHEST_SHARD}, not {shard}")
    return f"/* {MARKER} shard={shard} */ {sql}"


def _written(key: int | str) -> str:
    if isinstance(key, bool) or not isinstance(key, (int, str)):
        raise TypeError(
            f"a sharding key is an integer or a string, not {type(key).__name__}"
        )
    if isinstance(key, int):
        return str(key)
    if not key:
        raise ValueError("a hint with an empty key says nothing; shahrah refuses it")
    if "*/" in key or "\n" in key or "\r" in key:
        raise ValueError("a key in a hint cannot close the comment or break the line")
    return key
