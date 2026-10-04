#!/usr/bin/env python3
"""Drive the lab end to end (stdlib only; runs on the host).

1. Wait until every PBX has registered.
2. Run each scenario group from lab/scenarios.json with SIPp (entries of a
   group run concurrently), requiring every call to succeed.
   The "outage" group stops a receipt service during its calls, waits for the
   countersignature window, brings it back, then restarts every receipt service.
3. Flush the receipt services (exchange, STH, monitoring) a few times.
4. Run the assertions in lab/tests inside the "tester" container.
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
print(json.load(urllib.request.urlopen(r, timeout=30))['tree_size'])
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
        f"exec sipp -sf /scenarios/uac.xml -s {entry['dial']} -set caller {entry['caller']} "
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
    """Calls while the terminating receipt service is down, then recovery and restarts."""
    down = sorted({e["outage"] for e in entries})
    print(f"   stopping {down}")
    sh("stop", *down)
    run_group("outage calls", entries, header=False)
    print(f"   waiting {OUTAGE_WAIT}s for the countersignature window to expire")
    time.sleep(OUTAGE_WAIT)
    flush(rounds=1, pause=0, skip=set(down))
    print(f"   starting {down}")
    sh("start", *down)
    wait_healthy(down)
    flush(rounds=2)
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
        for node, svc in RECEIPTS.items():
            if skip and svc in skip:
                continue
            out = sh("exec", "-T", svc, "python", "-c", FLUSH.format(node=node), capture=True)
            sizes[node] = out.stdout.strip()
        print("log sizes:", sizes)
        time.sleep(pause)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--groups", default="normal,short_burst,duration_mismatch,outage")
    ap.add_argument("--skip-calls", action="store_true", help="only run the assertions")
    ap.add_argument("--verbose", action="store_true", help="list every assertion")
    args = ap.parse_args()
    scenarios = json.loads((ROOT / "lab/scenarios.json").read_text())["groups"]
    groups = [g for g in args.groups.split(",") if g]
    if not args.skip_calls:
        wait_registered()
        for g in groups:
            if g == "outage":
                flush(rounds=2)
                print("== outage: " + ", ".join(f"{e['name']} x{e['calls']}" for e in scenarios[g]))
                run_outage(scenarios[g])
            else:
                run_group(g, scenarios[g])
            time.sleep(3)  # let BYE-time events reach the receipt services
        flush()
    r = sh(
        "run",
        "--rm",
        "-e",
        f"DOTS_E2E_GROUPS={','.join(groups)}",
        "tester",
        "pytest",
        "-v" if args.verbose else "-q",
        "-p",
        "no:cacheprovider",
        "lab/tests",
        check=False,
    )
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
