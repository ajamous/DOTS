#!/usr/bin/env python3
"""Drive the lab end to end (stdlib only; runs on the host).

1. Wait until every PBX has registered.
2. Run each scenario group from lab/scenarios.json with SIPp (entries of a
   group run concurrently), requiring every call to succeed.
   The "outage" group stops a receipt service during its calls, waits for the
   countersignature window, brings it back, then restarts every receipt service.
3. Flush the receipt services (exchange, STH, monitoring) a few times.
4. Run the assertions in lab/tests inside the "tester" container.
5. Resolve one duration-mismatch dispute as the operators would (originator
   re-proposes, terminator approves the concession), then run the
   assertions in lab/tests/resolution (receipt in both logs, supplementary
   statement).
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = ["docker", "compose", "--project-directory", str(ROOT)]
RECEIPTS = {"node-a": "receipts-a", "node-b": "receipts-b", "node-c": "receipts-c"}
OUTAGE_WAIT = 35  # > DOTS_COUNTERSIG_WINDOW_S (30 in the lab)

FLUSH = """
import json, urllib.request
t = open('/state/{node}/token').read().strip()
r = urllib.request.Request('http://127.0.0.1:8080/internal/tick', method='POST',
                           headers={{'authorization': 'Bearer ' + t}})
d = json.load(urllib.request.urlopen(r, timeout=30))
print(d['tree_size'], d.get('spool_recovered', 0))
"""

INTERNAL = """
import json, sys, urllib.request
t = open('/state/{node}/token').read().strip()
r = urllib.request.Request('http://127.0.0.1:8080' + sys.argv[1], method=sys.argv[2],
                           headers={{'authorization': 'Bearer ' + t}})
try:
    print(urllib.request.urlopen(r, timeout=30).read().decode())
except urllib.error.HTTPError as e:
    print(e.read().decode())
"""


def sh(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run([*COMPOSE, *args], check=check, text=True, capture_output=capture)


def wait_registered(timeout: float = 90) -> None:
    deadline = time.time() + timeout
    for svc in ("node-a1", "node-a2", "node-b1", "node-c1"):
        while True:
            out = sh("exec", "-T", svc, "kamcmd", "ul.dump", "brief", check=False, capture=True)
            if "AoR: pbx" in out.stdout:
                break
            if time.time() > deadline:
                sys.exit(f"{svc}: PBX registration not visible")
            time.sleep(2)
    print("registrations visible on every instance (node-a2 via dmq_usrloc)")


def sipp(entry: dict, port: int) -> subprocess.Popen[str]:
    cmd = (
        'IP=$(hostname -i | awk "{print \\$1}"); '
        f"exec sipp -sf /scenarios/{entry.get('scenario', 'uac.xml')} -s {entry['dial']} "
        f"-set caller {entry['caller']} "
        f"-i $IP -mi $IP -p {port} -mp {port + 2000} -m {entry['calls']} -r {entry['rate']} "
        f"-l {entry['calls']} -d {entry['duration_ms']} -nostdin -timeout 120s -timeout_error "
        f"-trace_err -error_file /tmp/{entry['name']}.err {entry['target']}:5060"
    )
    return subprocess.Popen(
        [*COMPOSE, "exec", "-T", entry["uac"], "sh", "-c", cmd],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def wait_healthy(services: list[str], timeout: float = 120) -> None:
    deadline = time.time() + timeout
    for svc in services:
        while True:
            out = sh("ps", "--format", "{{.Health}}", svc, check=False, capture=True).stdout
            if "healthy" in out and "unhealthy" not in out:
                break
            if time.time() > deadline:
                sys.exit(f"{svc} did not become healthy")
            time.sleep(2)


def run_outage(entries: list[dict]) -> None:
    """Calls while a receipt service is down, then recovery (and optionally restarts)."""
    down = sorted({e["outage"] for e in entries})
    wait = max(e.get("outage_seconds", OUTAGE_WAIT) for e in entries)
    print(f"   stopping {down}")
    sh("stop", *down)
    run_group("outage calls", entries, header=False)
    print(f"   {', '.join(down)} stays down {wait}s")
    time.sleep(wait)
    flush(rounds=1, pause=0, skip=set(down))
    print(f"   starting {down}")
    sh("start", *down)
    wait_healthy(down)
    flush(rounds=2)
    if any(e.get("restart_all") for e in entries):
        every = list(RECEIPTS.values())
        print("   restarting every receipt service (log reload from Postgres)")
        sh("restart", *every)
        wait_healthy(every)


def run_group(name: str, entries: list[dict], header: bool = True) -> None:
    if header:
        print(f"== {name}: " + ", ".join(f"{e['name']} x{e['calls']}" for e in entries))
    procs = [(e, sipp(e, 5080 + 10 * i)) for i, e in enumerate(entries)]
    failed = []
    for e, p in procs:
        out, _ = p.communicate()
        if p.returncode != 0:
            failed.append(e["name"])
            print(out[-3000:])
    if failed:
        sys.exit(f"SIPp scenarios failed: {failed}")


def flush(rounds: int = 4, pause: float = 2.0, skip: set[str] | None = None) -> None:
    for _ in range(rounds):
        sizes = {}
        spooled = {}
        for node, svc in RECEIPTS.items():
            if skip and svc in skip:
                continue
            out = sh("exec", "-T", svc, "python", "-c", FLUSH.format(node=node), capture=True)
            size, recovered = out.stdout.split()
            sizes[node] = size
            spooled[node] = recovered
        print("log sizes:", sizes, "| recovered from spool:", spooled)
        time.sleep(pause)


def internal(node: str, method: str, path: str) -> dict:
    out = sh(
        "exec",
        "-T",
        RECEIPTS[node],
        "python",
        "-c",
        INTERNAL.format(node=node),
        path,
        method,
        capture=True,
    )
    return json.loads(out.stdout)


def resolve_one() -> str:
    """A re-proposes one A->C duration-mismatch call; C approves its concession."""
    open_ = internal("node-a", "GET", "/internal/disputes")["open"]
    leaf = next(
        d["dispute"]
        for d in open_
        if d["kind"] == "duration_mismatch" and d["term_node"] == "node-c" and d["resolvable"]
    )
    first = internal("node-a", "POST", f"/internal/disputes/{leaf}/resolve")
    print(
        f"== resolution: node-a re-proposes {leaf[:12]}…: {first['status']} ({first.get('detail')})"
    )
    if first["status"] != "needs_approval":
        sys.exit(f"expected the terminator to ask for approval, got {first}")
    print(
        "   node-c approves:",
        internal("node-c", "POST", f"/internal/disputes/{leaf}/approve")["status"],
    )
    second = internal("node-a", "POST", f"/internal/disputes/{leaf}/resolve")
    print("   node-a re-proposes again:", second["status"])
    if second["status"] != "resolved":
        sys.exit(f"resolution failed: {second}")
    return leaf


def pytest(groups: list[str], verbose: bool, *paths: str, env: dict[str, str] | None = None) -> int:
    extra = [x for k, v in (env or {}).items() for x in ("-e", f"{k}={v}")]
    r = sh(
        "run",
        "--rm",
        "-e",
        f"DOTS_E2E_GROUPS={','.join(groups)}",
        *extra,
        "tester",
        "pytest",
        "-v" if verbose else "-q",
        "-p",
        "no:cacheprovider",
        *paths,
        check=False,
    )
    return r.returncode


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--groups", default="normal,srtp,short_burst,duration_mismatch,recovery,outage")
    ap.add_argument("--skip-calls", action="store_true", help="only run the assertions")
    ap.add_argument("--verbose", action="store_true", help="list every assertion")
    args = ap.parse_args()
    scenarios = json.loads((ROOT / "lab/scenarios.json").read_text())["groups"]
    groups = [g for g in args.groups.split(",") if g]
    if not args.skip_calls:
        wait_registered()
        for g in groups:
            if any("outage" in e for e in scenarios[g]):
                flush(rounds=2)
                print(f"== {g}: " + ", ".join(f"{e['name']} x{e['calls']}" for e in scenarios[g]))
                run_outage(scenarios[g])
            else:
                run_group(g, scenarios[g])
            time.sleep(3)  # let BYE-time events reach the receipt services
        flush()
    rc = pytest(groups, args.verbose, "lab/tests", "--ignore=lab/tests/resolution")
    if rc or "duration_mismatch" not in groups:
        sys.exit(rc)
    leaf = resolve_one()
    flush(rounds=2)
    sys.exit(
        pytest(
            groups,
            args.verbose,
            "lab/tests/resolution",
            env={"DOTS_RESOLVED_DISPUTE": leaf},
        )
    )


if __name__ == "__main__":
    main()
