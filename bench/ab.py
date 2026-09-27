"""Two binaries, one bed, interleaved rounds.

Running the suite, changing the code, and running it again does not measure the
change. On this machine the same four participants drifted between 2.1% and 5.4%
across one afternoon, and three of them had not changed by a line. So a
before/after has to be two binaries standing beside each other in the same bed,
taking rounds in turn, so the machine's own drift lands on both.

    python3 ab.py --baseline HEAD --workload select --protocol prepared

`before` is built from a git ref in its own worktree with its own target
directory; `after` is the working tree. They are placed identically and the same
footing check that guards `harness.py` guards this, so a bed that has drifted
apart refuses rather than reports.

The number to read is the per-round difference. Medians of two separately noisy
series say less than the paired differences do, because the pairs share whatever
the machine was doing at the time.
"""

import argparse
import math
import os
import pathlib
import shutil
import statistics
import subprocess
import sys

import harness

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
ARMS = ["before", "after"]
BINARIES = {"before": "shahrah-before", "after": "shahrah-after"}


def run(*args, **kw):
    return subprocess.run(args, text=True, **kw)


def build_working_tree():
    print("  building the working tree")
    done = run("cargo", "build", "--release", "-p", "shahrah-proxy",
               cwd=ROOT, capture_output=True)
    if done.returncode:
        raise SystemExit(f"the working tree does not build:\n{done.stderr}")
    shutil.copy(ROOT / "target" / "release" / "shahrah-proxy", HERE / BINARIES["after"])


def build_baseline(ref, where):
    tree = pathlib.Path(where) / "tree"
    target = pathlib.Path(where) / "target"
    if not tree.exists():
        print(f"  checking {ref} out into {tree}")
        done = run("git", "worktree", "add", "--detach", str(tree), ref,
                   cwd=ROOT, capture_output=True)
        if done.returncode:
            raise SystemExit(f"cannot check out {ref}:\n{done.stderr}")
    at = run("git", "rev-parse", "--short", "HEAD", cwd=tree,
             capture_output=True).stdout.strip()
    print(f"  building the baseline at {at}")
    done = run("cargo", "build", "--release", "-p", "shahrah-proxy",
               cwd=tree, capture_output=True,
               env={**os.environ, "CARGO_TARGET_DIR": str(target)})
    if done.returncode:
        raise SystemExit(f"the baseline does not build:\n{done.stderr}")
    shutil.copy(target / "release" / "shahrah-proxy", HERE / BINARIES["before"])
    return at


def same_source(ref):
    """True when the working tree holds exactly what the baseline was built from.

    The binaries themselves are never byte-identical -- `debug = 1` bakes the
    target directory into them and the two arms build in different ones -- so
    the question has to be asked of the source rather than of the output.
    """
    dirty = run("git", "status", "--porcelain", cwd=ROOT, capture_output=True).stdout.strip()
    if dirty:
        return False
    here = run("git", "rev-parse", "HEAD", cwd=ROOT, capture_output=True).stdout.strip()
    there = run("git", "rev-parse", ref, cwd=ROOT, capture_output=True).stdout.strip()
    return bool(here) and here == there


def by_chance(cheaper, dearer):
    """A two-sided sign test on the paired rounds.

    Comparing the median difference to the spread, which is the obvious thing to
    do, throws away what makes pairing worth doing: the two arms met the same
    machine in the same round, so it is the *direction* each round points that
    carries the signal, not the size of a difference the bed can swamp. Seven
    rounds all pointing one way happen 1.6% of the time by chance, however noisy
    each round was.
    """
    rounds = cheaper + dearer
    if rounds == 0:
        return None
    lopsided = max(cheaper, dearer)
    tail = sum(math.comb(rounds, k) for k in range(lopsided, rounds + 1))
    return min(1.0, 2 * tail / (2 ** rounds))


def summarise(values):
    ordered = sorted(values)
    middle = statistics.median(ordered)
    spread = (ordered[-1] - ordered[0]) / middle * 100 if middle else 0.0
    return middle, ordered[0], ordered[-1], spread


def main():
    ask = argparse.ArgumentParser()
    ask.add_argument("--baseline", default="HEAD",
                     help="the git ref the `before` arm is built from")
    ask.add_argument("--worktree", default="/tmp/shahrah-ab",
                     help="where that ref is checked out and built")
    ask.add_argument("--clients", type=int, default=64)
    ask.add_argument("--seconds", type=int, default=10)
    ask.add_argument("--rounds", type=int, default=7)
    ask.add_argument("--workload", default="select1",
                     choices=["select1", "select2", "write", "select"])
    ask.add_argument("--protocol", default="simple",
                     choices=["simple", "extended", "prepared"])
    ask.add_argument("--scale", type=int, default=10)
    ask.add_argument("--skip-build", action="store_true")
    chosen = ask.parse_args()

    harness.FILES = ["compose.yaml", "compose.ab.yaml"]
    harness.FRONTS.update({arm: ["pg1"] for arm in ARMS})

    at = chosen.baseline
    if not chosen.skip_build:
        at = build_baseline(chosen.baseline, chosen.worktree)
        build_working_tree()

    if same_source(chosen.baseline):
        print("  note: the working tree holds exactly what the baseline was built "
              "from, so the two arms are the same program. Whatever this run "
              "reports is the bed talking, which is the only way to learn what the "
              "bed sounds like when nothing has changed.")

    print("  building the images")
    made = harness.compose("build", "--quiet", *ARMS)
    if made.returncode:
        raise SystemExit(f"the images do not build:\n{made.stderr}")

    standing = harness.compose("up", "-d", "--wait", "pg1", "client", *ARMS)
    if standing.returncode:
        raise SystemExit(f"the bed will not come up:\n{standing.stderr}")
    harness.seed(chosen.scale)
    try:
        _placed, latency = harness.footing(ARMS)
    except harness.Unequal as why:
        print(f"\nREFUSING TO REPORT A NUMBER.\n{why}\n")
        return 2
    print("  footing: identical placement, same database fronted, no host path")
    print("  fastest accept: " + ", ".join(f"{w} {v:.3f} ms" for w, v in latency.items()))

    print("  warming both arms; the first scored round is otherwise the bed "
          "waking up rather than the code")
    for arm in ARMS:
        harness.one_run(arm, chosen.clients, chosen.seconds, chosen.workload,
                        chosen.protocol)

    rates = {arm: [] for arm in ARMS}
    burnt = {arm: [] for arm in ARMS}
    paired = []
    for number in range(chosen.rounds):
        turn = ARMS if number % 2 == 0 else list(reversed(ARMS))
        this = {}
        for arm in turn:
            rate, spent = harness.one_run(arm, chosen.clients, chosen.seconds,
                                          chosen.workload, chosen.protocol)
            if rate is None:
                print(f"  round {number + 1}: {arm} answered nothing")
                continue
            rates[arm].append(rate)
            this[arm] = spent
            if spent is not None:
                burnt[arm].append(spent)
        if this.get("before") is not None and this.get("after") is not None:
            paired.append(this["after"] - this["before"])
            print(f"  round {number + 1}: before {this['before']:5.1f} us   "
                  f"after {this['after']:5.1f} us   "
                  f"delta {this['after'] - this['before']:+5.2f}")

    print(f"\n{chosen.workload}, {chosen.protocol} protocol, {chosen.clients} clients, "
          f"{chosen.rounds} interleaved rounds")
    print(f"  {'arm':8s} {'median ops/s':>13s} {'spread':>8s} {'median us':>11s} "
          f"{'min':>7s} {'max':>7s}")
    for arm in ARMS:
        if not rates[arm]:
            print(f"  {arm:8s} answered nothing in every round")
            continue
        middle, low, high, spread = summarise(rates[arm])
        if burnt[arm]:
            cpu, cheap, dear, _s = summarise(burnt[arm])
            print(f"  {arm:8s} {middle:13.0f} {spread:7.1f}% {cpu:11.1f} "
                  f"{cheap:7.1f} {dear:7.1f}")
        else:
            print(f"  {arm:8s} {middle:13.0f} {spread:7.1f}% {'-':>11s}")

    if not paired:
        print("\n  no round produced a CPU figure for both arms; there is no "
              "comparison here")
        return 2

    middle = statistics.median(paired)
    cheaper = sum(1 for one in paired if one < 0)
    dearer = sum(1 for one in paired if one > 0)
    base = statistics.median(burnt["before"]) if burnt["before"] else 0.0
    share = middle / base * 100 if base else 0.0
    print("\n  paired difference, after minus before, per round:")
    print("    " + "  ".join(f"{one:+.2f}" for one in sorted(paired)))
    print(f"  median {middle:+.2f} us per transaction ({share:+.1f}%), "
          f"cheaper in {cheaper} of {len(paired)} rounds, dearer in {dearer}")

    odds = by_chance(cheaper, dearer)
    if odds is None:
        print("  no round separated the two arms at all")
    elif odds > 0.05:
        print(f"  the rounds do not agree on a direction ({cheaper} against {dearer}, "
              f"which happens {odds * 100:.0f}% of the time by chance alone). This bed "
              f"cannot separate these two binaries: read it as no measured change.")
    else:
        favoured = "after" if cheaper > dearer else "before"
        print(f"  the rounds agree: {favoured} is cheaper in {max(cheaper, dearer)} of "
              f"{cheaper + dearer}, which happens {odds * 100:.1f}% of the time by chance. "
              f"The size of the difference is less certain than its direction -- the "
              f"per-round spread is {max(paired) - min(paired):.2f} us.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
