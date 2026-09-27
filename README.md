# shahrah

A PostgreSQL proxy that knows which region a user's data is in.

It shards by a key you name, splits reads from writes, pools connections, and —
the part nothing else does — keeps a directory of which region each key lives in,
routes to that region, and moves a key between regions while the application
keeps reading and writing.

Applications talk to it in the PostgreSQL wire protocol. There is no driver to
install and no shahrah-specific code in the request path.

## What it is for

Hundreds of millions of users, spread over regions, where a user's data should be
in the region they are in. Sharding alone puts a Tehran user's rows on whichever
shard the hash picks, and if that shard is in Virginia, every read crosses an
ocean. shahrah puts the region in front of the shard map rather than inside it,
so the shard a key lives on is chosen *within* its home region.

Measured on a three-region bed with the real latencies shaped in, a user's read:

| | data in the user's region | one region for everyone |
|---|---|---|
| a user in na-east | 0.15 ms | 0.17 ms |
| a user in eu-central | **0.20 ms** | 43.22 ms |
| a user in asia-west | **0.16 ms** | 76.16 ms |

Five rounds, 100 reads per region per arm. The na-east row is the honest cost: a
directory lookup that a single-region deployment does not have to do. See
`docs/NUMBERS.md` for the spreads, and for where shahrah is slower than the
alternatives.

## Running it against three shards

Three PostgreSQL servers, one topology file, one process.

```toml
# shards.toml
region = "na-east"

[policy.keys.users]
column = "id"
type = "int"

[[shards]]
number = 1
region = "na-east"
primary  = { address = "10.0.0.11:5432", region = "na-east" }
replicas = [{ address = "10.0.0.12:5432", region = "na-east" }]
logical  = [{ start = 0, end = 21844 }]

[[shards]]
number = 2
region = "na-east"
primary = { address = "10.0.0.21:5432", region = "na-east" }
logical = [{ start = 21845, end = 43689 }]

[[shards]]
number = 3
region = "na-east"
primary = { address = "10.0.0.31:5432", region = "na-east" }
logical = [{ start = 43690, end = 65535 }]
```

Every shard needs a role shahrah can log in as, and a function it can ask for a
user's stored verifier — shahrah never sees a password in the clear, and neither
do you:

```sql
create role shahrah login superuser password 'change-me';
create or replace function shahrah_get_auth(in wanted text,
                                            out username text, out verifier text)
returns record as $$
  select rolname::text, rolpassword::text from pg_authid where rolname = $1
$$ language sql security definer;
revoke all on function shahrah_get_auth(text) from public;
```

Then:

```bash
SHAHRAH_LISTEN=0.0.0.0:6432 \
SHAHRAH_CONFIG=/etc/shahrah/shards.toml \
SHAHRAH_BACKEND=10.0.0.11:5432 \
SHAHRAH_BACKEND_USER=shahrah \
SHAHRAH_BACKEND_PASSWORD=change-me \
SHAHRAH_METRICS_LISTEN=127.0.0.1:9187 \
  shahrah-proxy
```

Point the application at `postgresql://youruser:yourpassword@proxy:6432/yourdb`.
Nothing else changes.

### The settings that matter

| variable | what it does |
|---|---|
| `SHAHRAH_LISTEN` | where clients connect. |
| `SHAHRAH_CONFIG` | the topology file. Without one, every statement goes to `SHAHRAH_BACKEND` unchanged. |
| `SHAHRAH_BACKEND` | where shahrah reads the auth verifier, and the fallback backend. |
| `SHAHRAH_BACKEND_USER`, `SHAHRAH_BACKEND_PASSWORD` | how shahrah logs in to the shards. |
| `SHAHRAH_MAX_POOL` | connections per endpoint, per database, per role. |
| `SHAHRAH_METRICS_LISTEN` | serves the live dashboard at `/` and `/metrics`, `/snapshot`, `/key/<table>/<key>`. **Unset by default.** |
| `SHAHRAH_METRICS_PASSWORD` | the operator password. Without it shahrah **refuses to bind** anything but loopback, because the dashboard publishes the topology and where every user's data lives. |
| `SHAHRAH_METRICS_OPEN` | `yes` to serve a reachable address with no password anyway, for a deployment that has put its own authentication in front. |
| `SHAHRAH_METRICS_TLS_CERT`, `SHAHRAH_METRICS_TLS_KEY` | serve the dashboard over TLS. Without both it is plain HTTP, and shahrah says so when a password would cross a network in the clear. |
| `SHAHRAH_WARM_PER_SHARD` | connections opened at start so no session pays the first crossing. |
| `SHAHRAH_TRACE_SAMPLE` | trace one statement in N. |
| `SHAHRAH_AUTH_DATABASE` | which database the verifier is read from. `postgres` unless you say otherwise. |
| `SHAHRAH_AUTH_QUERY` | the statement that reads it, if `shahrah_get_auth` is not what you want to call it. |

### TLS

| variable | what it does |
|---|---|
| `SHAHRAH_TLS_CERT`, `SHAHRAH_TLS_KEY` | serve TLS to clients. Without both, shahrah answers `SSLRequest` with `N` and the connection continues in the clear. |
| `SHAHRAH_BACKEND_TLS` | `require` to insist on TLS to the shards. **Anything else, including unset, means `disable`** -- so this is opt-in, and a typo is silent. |
| `SHAHRAH_BACKEND_TLS_INSECURE` | accept a shard certificate shahrah cannot verify. For a test bed; not for anything else. |

### The directory

| variable | what it does |
|---|---|
| `SHAHRAH_DIRECTORY_TABLE` | the table each shard keeps the home regions in. `shahrah_directory`. |
| `SHAHRAH_DIRECTORY_CACHE` | how many home regions a proxy holds in memory. A million. |
| `SHAHRAH_DIRECTORY_TTL` | how long it trusts one before reading it again. 300 seconds. A move announced through the group invalidates it immediately, so this is the bound for a move shahrah was not told about. |

### More than one proxy

A single proxy needs none of these. They are how a group of them agrees on the
topology and hears about a key that moved.

| variable | what it does |
|---|---|
| `SHAHRAH_RAFT_ID` | this proxy's number in the group. |
| `SHAHRAH_RAFT_LISTEN` | where its peers reach it. |
| `SHAHRAH_RAFT_PEERS` | `1=host:port,2=host:port,...`, every member including this one. |
| `SHAHRAH_RAFT_STATE` | the file it keeps its log and state machine in. |
| `SHAHRAH_RAFT_BOOTSTRAP` | set on exactly one proxy, exactly once, to create the group. |
| `SHAHRAH_RAFT_SPREAD` | how the group carries the topology between members. |

### Connections

| variable | what it does |
|---|---|
| `SHAHRAH_RESET_QUERY` | run on a backend connection before it goes back in the pool. |
| `SHAHRAH_BACKEND_TIMEZONE` | the timezone shahrah sets on a backend connection. |

## Placing a table

A table is one of two things, and shahrah refuses to guess:

```toml
[policy.keys.users]      # geo-partitioned: rows live in one region, by this key
column = "id"
type = "int"             # int | text | uuid

[policy.replicated.plans]  # globally replicated: the same rows everywhere
writer_region = "na-east"  # written in one region, read from any
```

A statement against a geo-partitioned table that does not carry its key is
refused rather than sent somewhere hopeful. If the key is there but shahrah
cannot see it — a view, a join, an ORM you do not control — say so in a comment:

```sql
/* shahrah: key=7 */ select * from orders_view limit 50
```

## Asking where a user's data is

The console is a database called `shahrah`, spoken over the same wire protocol,
so psql reaches it:

```bash
psql -h proxy -p 6432 -U youruser shahrah -c 'WHERE IS users 100005'
```

```text
 answer     | learned_from                 | logical | shard | endpoint       | local
 eu-central | the directory, read just now |    6655 |     3 | 10.1.0.11:5432 | no
```

`SHOW HELP` lists the rest: `SHOW POOLS`, `SHOW HEALTH`, `SHOW TRAFFIC`,
`SHOW ALERTS`, `SHOW TOPOLOGY`, `SHOW PLACEMENT`, `SHOW DIRECTORY`,
`SHOW MOVERS`, `SHOW FLEET <subject>` for every proxy in the group at once, and
the verbs `DRAIN`, `UNDRAIN`, `RELOCATE`, `REBALANCE`, `REPAIR`, `TRACE`.

The console answers the **simple** query protocol. psql is fine; a driver that
prepares every statement gets a clear error rather than rows, and should read
`/metrics` instead.

## Moving a user to another region

```bash
psql -h proxy -p 6432 -U youruser shahrah -c 'RELOCATE users 100005 TO eu-central'
```

shahrah takes an intent marker on the key's directory row by compare-and-set —
so two operators racing produce one move and one refusal — copies the rows,
switches every region's copy of the directory, waits for the other proxies to
hear of it, and only then removes the rows it left behind. Statements for that
key are held for the moment of the cutover rather than answered from the wrong
place.

If a move is interrupted, `REPAIR` finishes it. If rows sit on the wrong shard of
the right region, `REBALANCE <region>` moves them.

## Watching it

`/metrics` is Prometheus text format: statements, refusals, per-endpoint traffic
and errors, pool occupancy, replica lag measured against the primary, and one
`shahrah_alert` series per condition worth waking someone for.

`/` is the dashboard, and it is **live**: it opens a WebSocket to `/live` and the
proxy pushes a snapshot every second, so the numbers move without the page
reloading under whoever is reading it. The first frame carries the last three
minutes of history so the charts are drawn before the first tick; every frame
after it carries one new sample, which is about 1.6 KB a second per viewer rather
than the 44 KB it would take to resend the history each time.

It lays out every database in every region with its state, role, replication lag
and traffic; rates over time for statements routed, statements reaching a shard,
statements crossing a region, refusals, backend errors, cache and directory hits,
and pool occupancy; a diagram of every region with its shards and their endpoints,
coloured by what the prober last saw; the conditions currently worth waking
someone for; what **every other proxy in the group** sees, named individually,
with an unreachable one named too; and a box to look up one user. It is built
from the fleet view rather than from this proxy's own, so **any proxy shows the
whole world**.

One page, no framework, no fonts or scripts fetched from anywhere: the charts are
SVG the page draws itself. If a proxy between the operator and shahrah refuses to
carry a WebSocket, the page notices after three attempts and falls back to polling
`/snapshot`, saying so in the corner rather than sitting there looking current
while it is not.

`/snapshot` is that same snapshot as JSON, for anything that would rather poll.
`/plain` is the dashboard without JavaScript — server-rendered, no live updates —
for a browser that will not run any.

`/key/<table>/<key>` is the page behind that box, and the one question no generic
dashboard can answer: where this user's data is, which shard holds it in each
region, and whether this proxy is the one nearest to it.

## Who may look

The metrics port shows your topology, your replica lag, and which region any
named user's rows are in. It asks for a password before it shows any of it.

Set `SHAHRAH_METRICS_PASSWORD` to something generated rather than something
chosen:

```bash
openssl rand -base64 32
```

It is compared as a constant-time equality of its SHA-256 — enough to leak
nothing by timing, but it is not a slow password hash, so a memorable password
would not survive its digest getting out. Generate it, keep it wherever you keep
secrets, and do not put it in a file you commit.

Without one, shahrah serves loopback with a
warning and **refuses to bind an address other machines can reach at all** —
there is no configuration in which it quietly listens to the network with
nothing in front of it. `SHAHRAH_METRICS_OPEN=yes` overrides that for a
deployment where something else already authenticates.

A browser signs in at `/login` and gets a session cookie: 32 random bytes,
`HttpOnly` so no script can read it, `SameSite=Strict` so no other site can
spend it, and twelve hours long. `/logout` ends it. Anything that is not a
browser — Prometheus, `curl` — sends the same password as
`Authorization: Bearer <password>` or HTTP Basic.

Guessing is bounded. Five wrong answers from one address and that address waits
30 seconds, then a minute, then two, up to fifteen; the right password does not
open the lock early. Every wrong answer costs the guesser a quarter of a second
whichever way it arrived, so a header is not a faster door than the form. Any one
address is held to 600 requests a minute across every path. The table of
addresses is itself bounded, because a table that grows with the attacker is the
denial of service it was meant to prevent.

The password is compared by constant-time equality of its SHA-256, so a wrong
guess takes the same time whatever it got right.

Set `SHAHRAH_METRICS_TLS_CERT` and `SHAHRAH_METRICS_TLS_KEY` and the port speaks
TLS: the dashboard over `https`, the live feed over `wss`, and the session cookie
gains `Secure` so a browser will not send it back over anything else. A cleartext
request to that port is not answered at all rather than downgraded. Without both
variables it is plain HTTP, and if a password would then be crossing an address
other machines can reach, shahrah says so at startup rather than leaving you to
assume otherwise.

The certificate is yours to provide and yours to rotate — shahrah reads it at
startup and does not watch the file.

**What this still does not do:** there is one password, not an account per
operator, so it says someone is an operator and not which one, and there is no
audit of who looked at what. `RELOCATE` and `DRAIN` remain on the console rather
than the dashboard, so the page reads and does not act.

## Building

```bash
cargo build --release
cargo test --workspace
```

The workspace denies `unsafe`, `unwrap`, `expect`, slicing that can panic, and
arithmetic that can overflow. There are no comments in the source: the names and
the tests are meant to carry it.

## Benchmarks

`bench/` brings up shahrah, pgbouncer, pgcat and PgDog on one network, refuses to
report a number until they are placed identically, and reports a distribution
rather than a figure. `bench/geo/` is the three-region bed the table above came
from. See `bench/README.md`.
