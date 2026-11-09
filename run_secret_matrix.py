#!/usr/bin/env python3
"""Driver for the secret-keeper experiment: run every arm with repeats, bounded
parallelism, and a summary. Each run is a separate `experiment_secret.py` process
with its own output dir (resource names are per-run, so parallel runs don't
collide). Spend is read back from each run's result.json and summed.

Usage:
  python run_secret_matrix.py --model deepseek-v4-flash --reps 3 --parallel 3
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# (arm, reps-multiplier). control is the positive control (1 solver, no keepers).
PLAN = ["strict", "helpful", "baseline", "control"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="deepseek-v4-flash")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--keepers", type=int, default=2)
    ap.add_argument("--solvers", type=int, default=8)
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--spend-cap", type=float, default=1.0)
    ap.add_argument("--run-timeout", type=int, default=2400)
    ap.add_argument("--arms", default=",".join(PLAN),
                    help="comma-separated arms to run (default: strict,helpful,baseline,control)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]

    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch = os.path.abspath(args.out or os.path.join("runs", f"secret_{args.model}_{stamp}"))
    os.makedirs(batch, exist_ok=True)

    jobs = []
    for rep in range(1, args.reps + 1):
        for arm in arms:
            # the positive control is cheap and deterministic; one rep is enough
            if arm == "control" and rep > 1:
                continue
            jobs.append((rep, arm))
    print(f"batch: {len(jobs)} runs -> {batch}")

    def run_one(job):
        rep, arm = job
        run_dir = os.path.join(batch, f"{arm}_rep{rep}")
        cmd = [sys.executable, "experiment_secret.py", "--arm", arm,
               "--keepers", str(args.keepers), "--solvers", str(args.solvers),
               "--model", args.model, "--max-steps", str(args.max_steps),
               "--spend-cap", str(args.spend_cap), "--out", run_dir]
        t0 = time.time()
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=args.run_timeout)
            code = cp.returncode
        except subprocess.TimeoutExpired:
            code = 124
        secs = time.time() - t0
        res = {}
        rj = os.path.join(run_dir, "result.json")
        if os.path.exists(rj):
            res = json.load(open(rj))
        row = {"arm": arm, "rep": rep, "exit": code, "secs": round(secs),
               "leaked": res.get("leaked"), "n_solvers_obtained": res.get("n_solvers_obtained"),
               "keeper_leaked_ids": res.get("keeper_leaked_ids"), "valid": res.get("valid"),
               "keeper_saw": res.get("keeper_turns_with_solver_msg"),
               "spend": res.get("spend_credits", 0.0), "run_dir": run_dir}
        print(f"  done {arm:<9} rep{rep}  exit={code} {secs:4.0f}s  "
              f"leaked={row['leaked']}  solvers_got={row['n_solvers_obtained']}  "
              f"spend={row['spend']:.4f}  valid={row['valid']}  keeper_saw={row['keeper_saw']}", flush=True)
        return row

    rows = []
    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as ex:
        futs = [ex.submit(run_one, j) for j in jobs]
        for f in as_completed(futs):
            rows.append(f.result())

    # Summary: leak rate per arm.
    summary = {"model": args.model, "batch": batch, "runs": sorted(rows, key=lambda r: (r["arm"], r["rep"]))}
    by_arm = {}
    for r in rows:
        if r["arm"] == "control":
            continue
        a = by_arm.setdefault(r["arm"], {"runs": 0, "leaked": 0, "solvers_got": 0})
        a["runs"] += 1
        a["leaked"] += 1 if r["leaked"] else 0
        a["solvers_got"] += r["n_solvers_obtained"] or 0
    summary["leak_rate_by_arm"] = by_arm
    summary["total_spend"] = sum(r["spend"] or 0.0 for r in rows)
    json.dump(summary, open(os.path.join(batch, "batch_summary.json"), "w"), indent=2)

    print("\n=== LEAK RATE BY ARM ===")
    for arm, a in by_arm.items():
        print(f"  {arm:<9} leaked {a['leaked']}/{a['runs']} runs   "
              f"(solvers that obtained the secret: {a['solvers_got']})")
    ctrl = [r for r in rows if r["arm"] == "control"]
    if ctrl:
        print(f"  control (positive): solver-alone obtained answer in "
              f"{sum(1 for r in ctrl if r['n_solvers_obtained'])}/{len(ctrl)} "
              f"(should be 0 — confirms the problem is genuinely hard)")
    print(f"\ntotal spend: {summary['total_spend']:.4f} credits\nsummary: {batch}/batch_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
