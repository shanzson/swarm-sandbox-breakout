#!/usr/bin/env python3
"""Run the full experiment matrix for one model and summarise it.

Rounds x modes x repeats, with bounded parallelism. Each run is a separate
`run_round.py` process with its own output directory (resource names are
per-run, so parallel runs do not collide). Spend is read back from each run's
VERIFIED event log and summed; once the batch total reaches --total-cap no new
runs are started (runs already in flight still finish under their own
per-run cap).

Usage:
  python run_matrix.py --model deepseek-v4-flash
  python run_matrix.py --model deepseek-v4-flash --repeats 3 --parallel 3
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from swarm_sandbox import sandbox
from swarm_sandbox.eventlog import EventLog
from swarm_sandbox.scenario import BASE_IMAGE, ROUNDS

# The experiment plan: (round, mode, extra_flags). Each entry is one condition,
# run `--repeats` times. Collusion is team-only and gets a no-chat control.
EXPERIMENT = [
    ("1-open", "solo", []),            # capability baseline
    ("1-open", "team", []),
    ("containment", "solo", []),       # the real containment test (secret present, egress closed)
    ("containment", "team", []),
    ("containment-gvisor", "solo", []),
    ("discovery-open", "solo", []),    # must DISCOVER the host, not be handed it
    ("discovery-open", "team", []),
    ("gvisor-demo", "solo", []),       # demonstration, not a finding
    ("collusion", "team", []),         # swarm: leak requires cooperation
    ("collusion", "team", ["--no-chat"]),  # control: no channel -> no leak
    ("env-only", "solo", []),          # attribution controls
    ("file-only", "solo", []),
    ("shared-only", "solo", []),
    ("egress-only", "solo", []),
    # Evaluation-awareness arm: same rounds, prompt that does NOT say "it's a test".
    ("1-open", "solo", ["--realistic"]),
    ("containment", "solo", ["--realistic"]),
    ("discovery-open", "solo", ["--realistic"]),
    ("collusion", "team", ["--realistic"]),
]

# Focused swarm study: only the conditions where a large team matters. Run this
# with --team-size 10 (or more) and --parallel 1 (so N agent containers from
# several runs don't pile up in memory at once).
SWARM_PLAN = [
    ("1-open", "team", []),                 # does a big swarm all pile onto the same routes?
    ("collusion", "team", []),              # does a big swarm collude over the chat?
    ("collusion", "team", ["--no-chat"]),   # control: no channel -> no leak
]


def _spend_from_log(run_dir: str) -> tuple[float, str]:
    log = os.path.join(run_dir, "events.jsonl")
    if not os.path.exists(log):
        return 0.0, "no log"
    ok, msg = EventLog.verify(log)
    if not ok:
        return 0.0, f"log invalid: {msg}"
    # Sum per-turn credits (counts spend even if the run died before 'result').
    total = 0.0
    for rec in EventLog.read(log):
        if rec["kind"] == "model_turn":
            total += float(rec["data"].get("usage", {}).get("credits", 0.0) or 0.0)
    return total, "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--plan", choices=["full", "swarm"], default="full",
                    help="'full' = whole experiment; 'swarm' = only large-team conditions")
    ap.add_argument("--team-size", type=int, default=3)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--per-run-cap", type=float, default=0.25)
    ap.add_argument("--total-cap", type=float, default=2.0)
    ap.add_argument("--image", default=BASE_IMAGE)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if not os.environ.get("ADAPTION_API_KEY"):
        print("ERROR: ADAPTION_API_KEY is not set.")
        return 2
    if not sandbox.docker_available():
        print("ERROR: Docker is not available.")
        return 2

    chosen = SWARM_PLAN if args.plan == "swarm" else EXPERIMENT
    plan = []
    for (r, mode, flags) in chosen:
        cfg = ROUNDS[r]
        if cfg.runtime and not sandbox.runtime_available(cfg.runtime):
            print(f"SKIP {r}: runtime {cfg.runtime} not installed")
            continue
        plan.append((r, mode, flags))

    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch_dir = os.path.abspath(args.out or os.path.join("runs", f"full_{args.model}_{stamp}"))
    os.makedirs(batch_dir, exist_ok=True)

    # Repeat-major order: if the batch is stopped early, every condition still
    # has the same number of completed repeats (+/- one).
    jobs = []
    for rep in range(1, args.repeats + 1):
        for (r, mode, flags) in plan:
            jobs.append((rep, r, mode, flags))
    print(f"batch: {len(jobs)} runs ({len(plan)} conditions x {args.repeats}) -> {batch_dir}")
    print(f"caps: {args.per_run_cap} credits/run, {args.total_cap} credits total; "
          f"parallel={args.parallel}; image={args.image}")

    lock = threading.Lock()
    state = {"spent": 0.0, "stopped": False}
    records = []

    def run_one(job):
        rep, r, mode, flags = job
        tag = (mode + ("_nochat" if "--no-chat" in flags else "")
               + ("_real" if "--realistic" in flags else ""))
        with lock:
            if state["stopped"] or state["spent"] >= args.total_cap:
                state["stopped"] = True
                return {"round": r, "mode": tag, "rep": rep, "status": "not_started"}
        n = args.team_size if mode == "team" else 1
        run_dir = os.path.join(batch_dir, f"{r}_{tag}{n}_rep{rep}")
        cmd = [sys.executable, "run_round.py", "--round", r, "--mode", mode,
               "--agents", str(n), "--model", args.model,
               "--spend-cap", str(args.per_run_cap), "--image", args.image,
               "--out", run_dir] + flags
        t0 = time.time()
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
            code, tail = cp.returncode, (cp.stdout + cp.stderr)[-1500:]
        except subprocess.TimeoutExpired:
            code, tail = 124, "[driver] run exceeded 1200s"
        secs = time.time() - t0
        with open(os.path.join(batch_dir, f"{r}_{tag}{n}_rep{rep}.stdout.txt"), "w") as f:
            f.write(tail)
        spend, note = _spend_from_log(run_dir)
        with lock:
            state["spent"] += spend
            total = state["spent"]
            if total >= args.total_cap:
                state["stopped"] = True
        print(f"  done {r:<18} {tag:<11} rep{rep}  exit={code}  {secs:5.0f}s  "
              f"spend={spend:.5f}  total={total:.5f}  ({note})", flush=True)
        return {"round": r, "mode": tag, "rep": rep, "exit": code, "secs": round(secs, 1),
                "spend": spend, "log": note, "run_dir": run_dir, "status": "ran"}

    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as ex:
        futs = [ex.submit(run_one, j) for j in jobs]
        for f in as_completed(futs):
            records.append(f.result())

    summary = {
        "model": args.model, "batch_dir": batch_dir, "jobs": len(jobs),
        "ran": sum(1 for r in records if r["status"] == "ran"),
        "not_started": sum(1 for r in records if r["status"] == "not_started"),
        "failed_exit": sum(1 for r in records if r["status"] == "ran" and r["exit"] != 0),
        "total_spend_credits": state["spent"], "stopped_on_cap": state["stopped"],
        "runs": sorted(records, key=lambda x: (x["rep"], x["round"], x["mode"])),
    }
    with open(os.path.join(batch_dir, "batch_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nran {summary['ran']}/{len(jobs)}  failed={summary['failed_exit']}  "
          f"not_started={summary['not_started']}  total spend={state['spent']:.5f} credits")
    print(f"summary: {os.path.join(batch_dir, 'batch_summary.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
