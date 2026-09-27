# bench/world

Five regions, ten databases, real streaming replication, and the distances
between them shaped in. This bed exists to be *looked at* rather than measured:
it is what the dashboard has to render when a deployment is not a toy.

```
./prepare.sh
docker compose up -d
open https://127.0.0.1:9187/
```

| region | primary | replica | shaped distance from the proxy |
|---|---|---|---|
| na-east | `pgne` | `pgner` | local |
| na-west | `pgnw` | `pgnwr` | 32 ms |
| eu-central | `pgeu` | `pgeur` | 42 ms |
| sa-east | `pgsa` | `pgsar` | 58 ms |
| asia-west | `pgas` | `pgasr` | 75 ms |

The replicas are real: each is `pg_basebackup`ed from its primary and left
streaming, so `pg_is_in_recovery()` answers true, the role the topology gives it
is one shahrah can check rather than take on trust, and the lag column is a
measurement rather than a dash. A fake replica would show `right role: NO` on
every row and teach nothing.

The distance is shaped per pair on the proxy's own interface, the way `bench/geo`
does it, so the proxy is far from a region while the databases are all beside
each other. Shaping the databases instead would make every participant equally
far from everything, which is not what a region is.

## What it is for

The proxy sits in na-east and the directory places keys across all five regions,
so most reads cross one. That is the shape that makes the dashboard's numbers
mean something: statements crossing a region, per-endpoint traffic spread over
ten nodes, and a latency panel where the bars are the map.

It also shows a thing worth knowing on its own: **a health probe's connect costs
about five round trips where its query costs one.** On the asia-west pair, 77 ms
to ask and 380 ms to open the connection to ask it on — TCP's handshake, then
SCRAM's, then the role. That is the cost a session pays when the pool has nothing
warm for it, and it is why `SHAHRAH_WARM_PER_SHARD` exists.

## Driving traffic through it

```
docker compose exec -d client bash -c "bash /world/spin.sh"
```

`work.sql` is a few thousand keyed reads with a scattering of writes; `spin.sh`
replays it in one session, forever. Run it two or three times for a busier page.

## Signing in

`prepare.sh` writes two things and neither is committed:

- `.env`, holding a fresh `openssl rand -base64 32` as the operator password.
  `compose.yaml` reads it as `${DASHBOARD_PASSWORD:?run ./prepare.sh first}`, so
  bringing the bed up without it fails with that sentence rather than starting
  something with a password somebody read in a git history.
- `tls/`, a self-signed certificate, so the bed serves `https` and `wss` and a
  browser complains about the certificate exactly once.

It prints the password. Scrapers and `curl` send it as Basic or Bearer:

```
curl -k -u op:"$(sed -n 's/^DASHBOARD_PASSWORD=//p' .env)" https://127.0.0.1:9187/metrics
```

Guess it wrong five times and this address waits, which is the point, but it also
means a mistyped password during a demo costs half a minute.

## This bed publishes a port

`world-proxy` maps 9187 and 6432 to the host, which `bench/harness.py` would
refuse in a comparison — a published port gives the load generator a second path
to a participant. Nothing here is a comparison: it is one proxy, looked at
through a browser, and the browser has to reach it.
