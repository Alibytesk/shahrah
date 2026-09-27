"""A FastAPI application that does not know shahrah is there.

Run it against a shahrah proxy exactly as you would against PostgreSQL:

    SHAHRAH_DSN=postgresql://app1:app1pw@127.0.0.1:6432/postgres uvicorn app:api

The request path below has no shahrah in it. That is the point: sharding,
read routing and region placement happen behind the wire protocol. The one
shahrah-specific route is /where/{user_id}, which asks the console a question
no ordinary database can answer.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

import shahrah

DSN = os.environ.get("SHAHRAH_DSN", "postgresql://app1:app1pw@127.0.0.1:6432/postgres")


@asynccontextmanager
async def lifespan(api: FastAPI):
    api.state.pool = await shahrah.pool(DSN, min_size=2, max_size=20)
    yield
    await api.state.pool.close()


api = FastAPI(lifespan=lifespan)


@api.get("/users/{user_id}")
async def read_user(user_id: int):
    async with api.state.pool.acquire() as connection:
        row = await connection.fetchrow("select id, name from users where id = $1", user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such user")
    return dict(row)


@api.put("/users/{user_id}")
async def write_user(user_id: int, name: str):
    async with api.state.pool.acquire() as connection:
        await connection.execute(
            "insert into users (id, name) values ($1, $2) "
            "on conflict (id) do update set name = excluded.name",
            user_id,
            name,
        )
    return {"id": user_id, "name": name}


@api.get("/orders/{user_id}")
async def read_orders(user_id: int):
    """A statement whose key shahrah cannot see, carried by a hint instead."""
    async with api.state.pool.acquire() as connection:
        rows = await connection.fetch(
            shahrah.by_key(user_id, "select * from orders_view limit 50")
        )
    return [dict(row) for row in rows]


@api.get("/where/{user_id}")
async def where(user_id: int):
    return await shahrah.where_is(DSN, "users", user_id)
