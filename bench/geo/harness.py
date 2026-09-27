import json, re, statistics, subprocess, sys, time

REGIONS = {"na-east": "pgna", "eu-central": "pgeu", "asia-west": "pgasia"}
ARMS = {
    "shahrah, data in the user's region": {
        "na-east": "geo-na", "eu-central": "geo-eu", "asia-west": "geo-asia",
    },
    "one region for everyone": {
        "na-east": "one-na", "eu-central": "one-eu", "asia-west": "one-asia",
    },
}
PEOPLE = 60
ROUNDS = 5


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True)


def inside(service, *args, password=None):
    env = ["-e", f"PGPASSWORD={password}"] if password else []
    return sh("docker", "compose", "-f", "compose.yaml", "exec", "-T", *env, service, *args)


def on(host, sql, quiet=True):
    out = inside("client", "psql", "-h", host, "-p", "5432", "-U", "postgres",
                 "-d", "postgres", "-tAc", f"set lock_timeout = '20s'; {sql}", password="dev")
    if not quiet and out.stderr.strip():
        print("   ", out.stderr.strip()[:200])
    return out.stdout.strip()


AUTH = ("create or replace function shahrah_get_auth(in wanted text, out username text, "
        "out verifier text) returns record as $$ select rolname::text, rolpassword::text "
        "from pg_authid where rolname = $1 $$ language sql security definer")


def hex_key(number):
    return int(number).to_bytes(8, "little", signed=True).hex()


def seed():
    for host in REGIONS.values():
        on(host, "create role app1 login password 'app1pw'")
        on(host, "create role shahrah login superuser password 'dev'")
        on(host, AUTH)
        on(host, "create table if not exists people(id bigint primary key, name text)")
        on(host, "create table if not exists shahrah_directory("
                 "shard_key bytea primary key, home_region text not null, moving_to text)")
        on(host, "delete from people")
        on(host, "delete from shahrah_directory")
        on(host, "grant all on people, shahrah_directory to app1")
    placed = {number: list(REGIONS)[number % len(REGIONS)] for number in range(PEOPLE)}
    rows = {host: [] for host in REGIONS.values()}
    directory = []
    for number, home in placed.items():
        rows[REGIONS[home]].append(f"({number}, 'person-{number}')")
        if REGIONS[home] != "pgna":
            rows["pgna"].append(f"({number}, 'person-{number}')")
        directory.append(f"('\\x{hex_key(number)}'::bytea, '{home}')")
    for host, values in rows.items():
        on(host, "insert into people values " + ", ".join(values)
                 + " on conflict (id) do nothing")
    for host in REGIONS.values():
        on(host, "insert into shahrah_directory (shard_key, home_region) values "
                 + ", ".join(directory)
                 + " on conflict (shard_key) do update set home_region = excluded.home_region")
    return placed


def read_many(proxy, ids):
    script = (
        "import asyncio,asyncpg,sys,json,time\n"
        "async def m():\n"
        f"    c=await asyncpg.connect('postgresql://app1:app1pw@{proxy}:6432/postgres')\n"
        "    seen=[]\n"
        "    for i in json.loads(sys.argv[1]):\n"
        "        at=time.perf_counter()\n"
        "        v=await c.fetchval('select name from people where id=$1', i)\n"
        "        seen.append([(time.perf_counter()-at)*1000, v is not None])\n"
        "    await c.close(); print(json.dumps(seen))\n"
        "asyncio.run(m())\n"
    )
    out = inside("client", "python3", "-c", script, json.dumps(ids))
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        print(f"    {proxy} did not answer: {out.stdout.strip()[:150]} {out.stderr.strip()[:200]}")
        return []


def main():
    print("seeding three regions ...")
    placed = seed()
    by_region = {}
    for number, home in placed.items():
        by_region.setdefault(home, []).append(number)

    inside("client", "python3", "-c", "import asyncpg")
    for arm, proxies in ARMS.items():
        for region, ids in by_region.items():
            read_many(proxies[region], ids[:3])

    per_round = {arm: [] for arm in ARMS}
    detail = {arm: {region: [] for region in by_region} for arm in ARMS}
    for number in range(ROUNDS):
        for arm, proxies in ARMS.items():
            every = []
            for region, ids in by_region.items():
                seen = read_many(proxies[region], ids)
                found = sorted(pair[0] for pair in seen if pair[1])
                if not found:
                    print(f"  round {number + 1}: {region} through {proxies[region]} "
                          "answered nothing")
                    continue
                detail[arm][region].extend(found)
                every.extend(found)
            if every:
                per_round[arm].append(statistics.median(sorted(every)))
        print(f"  round {number + 1}: "
              + "   ".join(f"{arm.split(',')[0]} {per_round[arm][-1]:.2f} ms"
                           for arm in ARMS if per_round[arm]))

    middles = {}
    for arm in ARMS:
        print(f"\n{arm}")
        for region in by_region:
            times = sorted(detail[arm][region])
            if not times:
                continue
            print(f"  {region:11s}: median {statistics.median(times):7.2f} ms   "
                  f"p95 {times[int(len(times) * 0.95)]:7.2f} ms   {len(times)} reads")
        if per_round[arm]:
            rounds = sorted(per_round[arm])
            middles[arm] = rounds
            print(f"  {'every user':11s}: median of {len(rounds)} rounds "
                  f"{statistics.median(rounds):7.2f} ms   "
                  f"lowest {rounds[0]:.2f}   highest {rounds[-1]:.2f}")

    if len(middles) == 2:
        fast = middles["shahrah, data in the user's region"]
        slow = middles["one region for everyone"]
        low = statistics.median(slow) / max(fast[-1], 0.001)
        high = statistics.median(slow) / max(fast[0], 0.001)
        print(f"\n  a user's read is {low:.0f}x to {high:.0f}x faster when their data lives in "
              f"their own region: {statistics.median(slow):.2f} ms against "
              f"{statistics.median(fast):.2f} ms")
        print("  the ratio moves because the fast side is under a millisecond and the slow side "
              "is an ocean; the two absolute numbers are the result, not the multiple")
    return 0


if __name__ == "__main__":
    sys.exit(main())
