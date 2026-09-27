# bench

One command, every participant on identical footing, a distribution rather than a
figure.

```
./bench/run.sh --suite single --clients 64 --seconds 20 --rounds 5
```

`run.sh` builds `shahrah-proxy`, builds the images, brings the bed up and runs the
harness. Nothing runs on the host: the load generator is a container on the same
network as the participants, and every participant reaches the databases by the
same DNS names.

## Suites

A comparison is only fair between participants doing the same work, so the
participants are grouped by what they front.

| suite | participants | fronts |
|---|---|---|
| `single` | shahrah, pgbouncer, pgcat, pgdog | `pg1` |
| `sharded` | shahrah, pgdog | `pg1`, `pg2`, `pg3` |

pgbouncer and pgcat are not in the sharded suite because they would be answering a
different question.

## Why it refuses

Two head-to-heads in this project were published wrong before they were right, both
times because the participants were not placed the same way -- once shahrah on the
host against a containerised rival, once shahrah reaching shards through mapped
ports while PgDog used container IPs. Correcting the second reversed the result.

So the harness will not print a number until it has checked, and it names what
differs when it refuses:

- every participant on the same networks, with the same CPU and memory limits
- no participant publishing a port to the host, which would give the load
  generator a second path to it
- every participant resolving the databases it is configured to front
The time each participant takes to accept a connection is reported beside the
result but **not enforced**. It was meant to be the placement check -- a TCP
connect involves no query -- and it is not one: accept is served by the
participant's own event loop, and pgcat repeatably takes 0.10 ms against
pgbouncer's 0.06 on identical placement. A check that cannot tell distance from
code would reject a fair comparison, which is worse than not checking. The
structural list above is what refuses; the timing is an observation.

## Why it interleaves

This machine drifts. The same workload measured 9 023, 8 080, 7 409 and 7 807
operations per second across four consecutive rounds with nothing changed -- a 22%
spread, on a hybrid CPU where which core a task lands on is part of the
measurement. Rounds are therefore run A, B, C, A, B, C rather than all of A then
all of B, so drift lands on everyone equally, and the report gives min, median, max
and spread. If the widest spread is over 10% of its own median the harness says so.

## What is deliberately simplified

Every shard is loaded with the same `pgbench` data, so a key-routed read always
finds its row without a loader that pre-splits the rows first. That measures the
routing path fairly -- both sharding participants do the same work -- but it is not
a sharded dataset, and the geo benchmark will need one.
