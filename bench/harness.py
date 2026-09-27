import argparse, json, os, re, statistics, subprocess, sys, time

NETWORK = "shahrah-bench"
FILES = ["compose.yaml", "compose.pool.yaml"]
DATABASES = ["pg1", "pg2", "pg3"]
SUITES = {
    "single": ["shahrah1", "pgbouncer", "pgcat", "pgdog1"],
    "sharded": ["shahrah", "pgdog"],
    # shahrah with no topology forwards every statement unchanged, which is the
    # job pgbouncer does. Anything else compares pooling against pooling plus a
    # routing decision.
    "pool": ["pool2", "pool1", "shahrah1", "pgbouncer"],
}
FRONTS = {
    "shahrah1": ["pg1"], "pgbouncer": ["pg1"], "pgcat": ["pg1"], "pgdog1": ["pg1"],
    "shahrah": ["pg1", "pg2", "pg3"], "pgdog": ["pg1", "pg2", "pg3"],
    "pool2": ["pg1"], "pool1": ["pg1"],
}
ACCEPT_NOTE = 0.35
AUTH_FUNCTION = """
create or replace function shahrah_get_auth(in wanted text,
                                            out username text, out verifier text)
returns record as $$
  select rolname::text, rolpassword::text from pg_authid where rolname = $1
$$ language sql security definer;
revoke all on function shahrah_get_auth(text) from public;
"""


def sh(*args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def spelled():
    return [part for name in FILES for part in ("-f", name)]


def compose(*args):
    return sh("docker", "compose", *spelled(), *args)


def inside(service, *args, password=None):
    env = ["-e", f"PGPASSWORD={password}"] if password else []
    return sh("docker", "compose", *spelled(), "exec", "-T", *env, service, *args)


def inspect(service, template):
    name = sh("docker", "compose", *spelled(), "ps", "-q", service).stdout.strip()
    if not name:
        return None
    return sh("docker", "inspect", "-f", template, name).stdout.strip()


class Unequal(Exception):
    pass


def footing(participants):
    report = []
    shape = {}
    for who in participants:
        networks = inspect(who, "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}")
        if networks is None:
            raise Unequal(f"{who} is not running")
        cpus = inspect(who, "{{.HostConfig.NanoCpus}}")
        memory = inspect(who, "{{.HostConfig.Memory}}")
        ports = inspect(who, "{{len .NetworkSettings.Ports}}")
        bound = inspect(who, "{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}")
        shape[who] = (tuple(sorted(networks.split())), cpus, memory)
        report.append((who, networks.strip(), cpus, memory, bound or "-"))

    distinct = {value for value in shape.values()}
    if len(distinct) > 1:
        lines = "\n".join(f"    {w}: networks={n} cpus={c} memory={m}" for w, n, c, m, _b in report)
        raise Unequal(
            "the participants are not placed identically, so any number from them "
            f"would compare their placement rather than their code:\n{lines}"
        )
    for who, _n, _c, _m, bound in report:
        if bound != "-":
            raise Unequal(
                f"{who} publishes {bound} to the host: the load generator could reach it "
                "by a different path than the others"
            )

    reached = {}
    for who in participants:
        for host in FRONTS[who]:
            seen = inside(who, "getent", "hosts", host).stdout.split()
            if not seen:
                raise Unequal(f"{who} cannot resolve {host}, which it is configured to front")
            reached.setdefault(who, []).append(seen[0])
    fronts = {who: tuple(FRONTS[who]) for who in participants}
    if len({tuple(sorted(v)) for v in fronts.values()}) > 1:
        lines = "\n".join(f"    {w}: {', '.join(v)}" for w, v in fronts.items())
        raise Unequal(
            "the participants do not front the same databases, so they are not "
            f"being asked to do the same work:\n{lines}"
        )

    probe = (
        "import socket,sys,time\n"
        "hosts=sys.argv[1:]\n"
        "best={h:9e9 for h in hosts}\n"
        "for round in range(6):\n"
        "    for h in hosts:\n"
        "        for _ in range(50):\n"
        "            at=time.perf_counter()\n"
        "            s=socket.create_connection((h,6432),2)\n"
        "            took=(time.perf_counter()-at)*1000\n"
        "            s.close()\n"
        "            if round and took<best[h]: best[h]=took\n"
        "print(' '.join(f'{h} {best[h]:.4f}' for h in hosts))\n"
    )
    spoken = inside("client", "python3", "-c", probe, *participants).stdout.split()
    latency = {spoken[i]: float(spoken[i + 1]) for i in range(0, len(spoken) - 1, 2)}
    if len(latency) != len(participants):
        raise Unequal(f"the reachability probe did not answer for every participant: {spoken}")
    return report, latency


def seed(scale):
    loaded: dict[str, int] = {}
    for host in DATABASES:
        inside("client", "psql", "-h", host, "-p", "5432", "-U", "postgres", "-d", "postgres",
               "-c", "create role app1 login password 'app1pw'", password="dev")
        inside("client", "psql", "-h", host, "-p", "5432", "-U", "postgres", "-d", "postgres",
               "-c", "create role shahrah login superuser password 'dev'", password="dev")
        inside("client", "psql", "-h", host, "-p", "5432", "-U", "postgres", "-d", "postgres",
               "-c", AUTH_FUNCTION, password="dev")
        done = inside("client", "psql", "-h", host, "-p", "5432", "-U", "postgres",
                      "-d", "postgres", "-tAc",
                      "select count(*) from pgbench_accounts", password="dev").stdout.strip()
        if done and done.isdigit() and int(done) > 0:
            loaded[host] = int(done)
            continue
        inside("client", "pgbench", "-i", "-s", str(scale), "-q",
               "-h", host, "-p", "5432", "-U", "postgres", "postgres", password="dev")
        inside("client", "psql", "-h", host, "-p", "5432", "-U", "postgres", "-d", "postgres",
               "-c", "grant all on all tables in schema public to app1", password="dev")
        loaded[host] = int(scale) * 100_000
    return loaded


def cpu_used(who):
    out = inside(who, "cat", "/sys/fs/cgroup/cpu.stat").stdout
    found = re.search(r"usage_usec (\d+)", out)
    return int(found.group(1)) if found else None


def one_run(who, clients, seconds, workload, protocol="simple"):
    args = ["pgbench", "-n", "-c", str(clients), "-j", "4", "-T", str(seconds),
            "-h", who, "-p", "6432", "-U", "app1", "--protocol", protocol]
    if workload in ("select1", "select2", "write"):
        args += ["-f", f"/bench/workloads/{workload}.sql"]
    else:
        args += ["-S"]
    args += ["postgres"]
    before = cpu_used(who)
    out = inside("client", *args, password="app1pw").stdout
    after = cpu_used(who)
    found = re.search(r"tps = ([0-9.]+)", out)
    if not found:
        return None, None
    rate = float(found.group(1))
    done = re.search(r"number of transactions actually processed: (\d+)", out)
    spent = None
    if before is not None and after is not None and done and int(done.group(1)):
        spent = (after - before) / int(done.group(1))
    return rate, spent


def main():
    ask = argparse.ArgumentParser()
    ask.add_argument("--suite", default="single", choices=sorted(SUITES))
    ask.add_argument("--clients", type=int, default=64)
    ask.add_argument("--seconds", type=int, default=10)
    ask.add_argument("--rounds", type=int, default=5)
    ask.add_argument("--workload", default="select1",
                     choices=["select1", "select2", "write", "select"])
    ask.add_argument("--protocol", default="simple",
                     choices=["simple", "extended", "prepared"])
    ask.add_argument("--scale", type=int, default=10)
    chosen = ask.parse_args()

    participants = SUITES[chosen.suite]
    print(f"suite {chosen.suite}: {', '.join(participants)}")
    loaded = seed(chosen.scale)
    sizes = sorted(set(loaded.values()))
    if sizes != [int(chosen.scale) * 100_000]:
        print(f"  note: the shards already hold {sizes} rows, not the {chosen.scale} scale asked "
              "for. Drop the volumes to reload.")
    compose("up", "-d", "--wait", *participants)
    try:
        placed, latency = footing(participants)
    except Unequal as why:
        print(f"\nREFUSING TO REPORT A NUMBER.\n{why}\n")
        return 2
    print("  footing: identical placement, same databases fronted, no host path")
    floor = min(latency.values())
    print("  fastest accept: "
          + ", ".join(f"{w} {v:.3f} ms" for w, v in latency.items()))
    apart = [w for w, v in latency.items() if v > floor * (1 + ACCEPT_NOTE)]
    if apart:
        print(f"  note: {', '.join(apart)} accept connections more slowly than the fastest. "
              "This is reported, not enforced: accept is served by the participant's own "
              "event loop, so it cannot tell distance from code.")

    for who in participants:
        one_run(who, chosen.clients, 3, chosen.workload, chosen.protocol)

    rounds = {who: [] for who in participants}
    burnt = {who: [] for who in participants}
    broken: dict[str, int] = {}
    for number in range(chosen.rounds):
        for who in participants:
            rate, spent = one_run(who, chosen.clients, chosen.seconds,
                                  chosen.workload, chosen.protocol)
            if rate is None:
                broken.setdefault(who, 0)
                broken[who] += 1
                continue
            rounds[who].append(rate)
            if spent is not None:
                burnt[who].append(spent)
        line = "  ".join(
            f"{who} {rounds[who][-1]:8.0f}" if rounds[who] else f"{who} {'no answer':>8s}"
            for who in participants
        )
        print(f"  round {number + 1}: {line}")

    print(f"\n{chosen.workload}, {chosen.protocol} protocol, {chosen.clients} clients, "
          f"{chosen.rounds} interleaved rounds")
    print(f"  {'participant':12s} {'median':>9s} {'min':>9s} {'max':>9s} {'spread':>8s} "
          f"{'us of CPU each':>15s}")
    for who in participants:
        values = sorted(rounds[who])
        if not values:
            print(f"  {who:12s} {'answered nothing in every round':>50s}")
            continue
        middle = statistics.median(values)
        spread = (values[-1] - values[0]) / middle * 100 if middle else 0.0
        cpu = f"{statistics.median(burnt[who]):15.1f}" if burnt[who] else f"{'-':>15s}"
        print(f"  {who:12s} {statistics.median(values):9.0f} {values[0]:9.0f} "
              f"{values[-1]:9.0f} {spread:7.1f}% {cpu}")
    if broken:
        for who, count in sorted(broken.items()):
            print(f"  {who} did not answer in {count} of {chosen.rounds} rounds; those rounds "
                  "are left out rather than counted as zero")
    answered = [who for who in participants if rounds[who]]
    if not answered:
        print("\n  nobody answered; there is no result here")
        return 2
    best = max(answered, key=lambda w: statistics.median(rounds[w]))
    print(f"\n  fastest median: {best}")
    worst = max((sorted(rounds[w])[-1] - sorted(rounds[w])[0]) / max(statistics.median(rounds[w]), 1)
                for w in answered) * 100
    if worst > 10:
        print(f"  the widest spread is {worst:.0f}% of its own median: on this machine a "
              f"single run is not a measurement")
    return 0


if __name__ == "__main__":
    sys.exit(main())
