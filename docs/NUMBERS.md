# The numbers

Every number here came from `bench/`, which refuses to report anything until the
participants are on identical footing, runs them interleaved so drift lands on
everyone, and reports a distribution rather than a figure. The bed is one
machine: an i3-1315U with 2 performance cores and 4 efficiency cores, each
participant capped at 2 CPUs and 1 GiB, all of them containers on one network
reaching PostgreSQL 18 by DNS name. Nothing runs on the host.

**Read the spreads before the medians.** On this machine the same workload has
measured 9 023, 8 080, 7 409 and 7 807 operations per second in four consecutive
rounds with nothing changed. A single run is not a measurement here, and the
tables below give min and max for that reason.

## What shahrah is slower at, and by how much

64 clients, `SELECT 1` — no table, so this is the cost of moving bytes through a
proxy and nothing else. 5 interleaved rounds.

| | µs of CPU each |
|---|---|
| pgbouncer | **21.5** |
| shahrah | **32.6** |
| PgDog | 42.2 |
| pgcat | 51.1 |

shahrah spent 52 µs here until the write path was buffered and the runtime was
sized to the container's CPU quota. It issued **seven write syscalls per
transaction where two suffice** — one per protocol frame — and started six worker
threads inside a two-CPU cap. Both are fixed; the count is now exactly 2.00.

64 clients, `pgbench -S` — a real keyed read, every statement carrying a
different literal.

| | µs of CPU each |
|---|---|
| pgbouncer | **28.8** |
| shahrah | **54.5** |
| pgcat | 58.5 |
| PgDog | 65.5 |

A first pass at this table had PgDog at 49.1 and shahrah behind it. That run was
taken while the bed was drifting -- pgbouncer's own spread in it was 44% -- and it
contradicted every other measurement, so it was taken again twice. The numbers
above are the median of those two runs; the discarded one is named here rather
than quietly dropped.

Three shards, keyed reads, shahrah against the only other participant that can
route them:

| | µs of CPU each |
|---|---|
| shahrah | **50.7** |
| PgDog | 62.5 |

**shahrah is cheaper than pgcat and PgDog on the routing-free workload and
still about half again pgbouncer's cost.**
pgbouncer spends 21 µs per transaction where every proxy built on tokio spends
41 to 52 — shahrah, pgcat and PgDog alike. Taking a statement apart to find its
key costs 13 µs of shahrah's total; the other 49 is the pass-through path it
shares with the other two. This is an architecture difference, not an
optimisation that was missed, and pgbouncer has twenty years of tuning on a much
narrower problem. **And the claim this project used to make against pgbouncer no longer holds
either.** asyncpg names every prepared statement per connection, those names
collide across a transaction pool, and pgbouncer used to break on it -- but
pgbouncer 1.25.2 handles it: forty concurrent asyncpg clients multiplexed over a
two-connection server pool, thirty prepared statements each, zero failures, the
same as shahrah. That was fixed in pgbouncer 1.21 in 2023. **shahrah has no
pooling advantage over pgbouncer.** What it has is sharding and geography.

**Against PgDog and pgcat shahrah is now cheaper on every workload measured** --
8, 64 and 256 clients, one shard and three, with and without a key to extract.
That was not true this morning: it took buffering the write path and sizing the
runtime to the container's CPU quota, both of which were shahrah's own waste
rather than anything the others do better.

## What changed while measuring

Two attempts, one that failed and one that worked. Both are here because the one
that failed is the more useful result.

**Thread-per-core with connection affinity: no.** P2 attributed about 20% to
cross-thread wakeup and named this as the fix; P3 repeated it. Built and measured
over nine interleaved rounds it moved nothing — 54.1 µs against 54.9 — and at six
cores with workers matched to them it was actively worse: **8% less CPU per
transaction and 20% less throughput**, because connections pinned at accept time
stay pinned and a work-stealing runtime rebalances where static affinity cannot.
It was removed.

**A cache on the shape of a statement rather than its text: yes, and it was the
largest single change in the project.** The statement cache was keyed on the SQL
text, so a client that inlines its literals — which is what the simple query
protocol means, and what pgbench does — missed on every statement and paid a full
parse each time. Keying on the token stream with the constants replaced, and
lifting the key out of the one remaining literal, cut a keyed read from **93.9 µs
to 60.8 µs of CPU** and raised its throughput **55%**. On three shards it took
102.2 µs down to 72.6 and closed most of the distance to PgDog.

The cache verifies itself when it stores a shape: it re-extracts the key from the
statement it just parsed and only caches the shape if it reads back identical.
The first thing that check caught was `where id = -1`, where the lexer sees `-`
and `1` as two tokens and the parser folds them into one constant — the cache
would have routed every negative key to the shard for its absolute value.

## The number the others cannot produce

Three regions, the real latencies shaped in per pair — 42 ms between North
America and Europe, 75 ms to Asia, 110 ms between Europe and Asia — a proxy in
each region, and users whose data is either placed in their own region or all in
one.

Five interleaved rounds, 100 reads per region per arm.

| a user in | data in the user's region | one region for everyone |
|---|---|---|
| na-east | 0.15 ms | 0.17 ms |
| eu-central | **0.20 ms** | 43.22 ms |
| asia-west | **0.16 ms** | 76.16 ms |
| every user, median of rounds | **0.15 ms** (0.14 – 0.29) | 43.18 ms (43.11 – 43.72) |

**0.15 ms against 43.18 ms.** Stated as a multiple that is 150x to 318x
depending on the round, and the spread is the point: the slow side is an ocean
and barely moves, the fast side is under a millisecond and is mostly noise. The
two absolute numbers are the result; the multiple is not a measurement.

The na-east row is the honest cost: placing data by region means asking a
directory where it is, which a single-region deployment never has to do.

A benchmark with one entrant proves nothing, so the comparison is against what
people actually do rather than against nobody: one region, everyone else pays the
ocean. Sharding without geography lands in the same place — it puts a third of
the users in each region and reads them from wherever the hash sent them.

The p95 column of the geo run is worth reading too: 43 ms for eu-central and
77 ms for asia-west, against medians under a millisecond. That is the first read
of a key whose home this proxy has not yet learned. The directory cache turns the
second read into a hash lookup; the first one crosses.

## Reproducing this

```bash
./bench/run.sh --suite single --clients 64 --seconds 12 --rounds 7
./bench/run.sh --suite sharded --clients 64 --seconds 12 --rounds 5 --workload select
cd bench/geo && docker compose up -d --wait && python3 harness.py
```

## Which column to trust

Run the single suite twice on this machine and the throughput medians move by
about 7% while the CPU per transaction moves by less than 2% -- shahrah 57.3 then
58.2, pgbouncer 22.1 then 23.1, pgcat 48.8 then 48.7, PgDog 45.2 then 45.6.
**CPU per transaction is the reproducible column here.** Throughput on a
six-core laptop under a container cap is a measurement of the laptop as much as
of the proxy.
