import asyncio, sys
sys.path.insert(0, "/repo/python")
import shahrah

DSN = "postgresql://app1:app1pw@geo-eu:6432/postgres"

async def main():
    pool = await shahrah.pool(DSN, min_size=1, max_size=4)
    async with pool.acquire() as c:
        row = await c.fetchrow("select id, name from people where id = $1", 1)
        print("  a read with no shahrah in the request path:", dict(row) if row else None)
        hinted = shahrah.by_key(1, "select id, name from people where id = 1")
        row = await c.fetch(hinted)
        print("  the same read carried by a hint:", [dict(r) for r in row])
    await pool.close()
    try:
        print("  where_is:", shahrah.where_is(DSN, "people", 1))
        print("  health:  ", shahrah.health(DSN)[:2])
    except RuntimeError as why:
        print("  console:", str(why)[:160])
asyncio.run(main())
