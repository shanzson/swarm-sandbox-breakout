#!/usr/bin/env python3
"""Deterministic replay of a recorded run, with no model and no API.

It reads the agent's commands from a run's tamper-evident log and re-runs those
exact commands in a fresh sandbox of the same round, then reports whether the
same routes succeed. This checks that a result reproduces from the record alone;
because hosted models have no seed, re-running the *model* is a separate, N-seed
job (see README), not what this does.

For faithful replay it reuses the recorded decoy tokens, and it rewrites the
recorded sink address to the replay sink's address, so commands that embedded a
literal token or IP still reproduce. In team mode each agent's commands are
replayed in that agent's own container.

Usage:  python rerun.py runs/<run-id>
"""

from __future__ import annotations

import argparse
import os

from swarm_sandbox import sandbox
from swarm_sandbox.eventlog import EventLog
from swarm_sandbox.scenario import ROUNDS, Scenario
from swarm_sandbox.tools import ALL_ROUTES


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    args = ap.parse_args()

    log_path = os.path.join(args.run_dir, "events.jsonl")
    ok, msg = EventLog.verify(log_path)
    print(f"log integrity: {msg}")
    if not ok:
        print("REFUSING to replay a tampered log.")
        return 2

    recs = EventLog.read(log_path)
    cfg_rec = next(r for r in recs if r["kind"] == "run_config")
    round_name = cfg_rec["data"]["round"]
    cfg = ROUNDS[round_name]

    scen_rec = next((r for r in recs if r["kind"] == "scenario"), None)
    old_tokens = scen_rec["data"]["tokens"] if scen_rec else {}
    old_sink = scen_rec["data"].get("sink_addr", "") if scen_rec else ""

    # Commands per agent, in order.
    per_agent: dict[str, list[str]] = {}
    for r in recs:
        if r["kind"] == "action":
            per_agent.setdefault(r["data"]["agent_id"], []).append(r["data"]["cmd"])
    total = sum(len(v) for v in per_agent.values())
    print(f"replaying {total} commands from {len(per_agent)} agent(s), round {round_name}")

    if not sandbox.docker_available():
        print("ERROR: Docker not available.")
        return 2

    run_dir = os.path.abspath(os.path.join(args.run_dir, "replay"))
    os.makedirs(run_dir, exist_ok=True)
    scen = Scenario(run_dir=run_dir, cfg=cfg)
    if old_tokens:
        scen.tokens = dict(old_tokens)   # reuse recorded decoys BEFORE setup generates new ones
    scen.setup()

    def _fix(cmd: str) -> str:
        # Point any literal old sink IP at the replay sink.
        if old_sink and scen.sink_addr and old_sink != scen.sink_addr:
            return cmd.replace(old_sink, scen.sink_addr)
        return cmd

    containers = []
    try:
        for agent_id, cmds in sorted(per_agent.items()):
            c = scen.start_agent(name_prefix=f"replay_{agent_id}")
            containers.append(c)
            for cmd in cmds:
                code, _ = c.exec(_fix(cmd))
                print(f"  [{agent_id}][{code}] {cmd[:66]}")
        succ = scen.successes()
    finally:
        scen.teardown(containers)

    print("\nreplay successes:")
    for route in ALL_ROUTES:
        if route in ("metadata", "privilege"):
            continue
        print(f"  {route:<15}{succ.get(route)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
