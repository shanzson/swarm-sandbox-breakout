"""End-to-end round test with the mock agent. Needs Docker; skipped without it."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from swarm_sandbox import sandbox
from swarm_sandbox.broker import Agent, Limits, run_episode
from swarm_sandbox.eventlog import EventLog
from swarm_sandbox.mock import MockClient
from swarm_sandbox.scenario import ROUNDS, Scenario

pytestmark = pytest.mark.skipif(
    not sandbox.docker_available(), reason="Docker not available"
)

DOORS = ("env_secret", "file_secret", "shared_volume", "egress", "docker_socket")


def _run(round_name, tmp_path):
    cfg = ROUNDS[round_name]
    if cfg.runtime and not sandbox.runtime_available(cfg.runtime):
        pytest.skip(f"runtime {cfg.runtime} not installed")
    run_dir = str(tmp_path / round_name)
    os.makedirs(run_dir, exist_ok=True)
    log = EventLog(os.path.join(run_dir, "events.jsonl"))
    scen = Scenario(run_dir=run_dir, cfg=cfg)
    scen.setup()
    c = None
    try:
        c = scen.start_agent()
        agents = [Agent("A0", MockClient(), c)]
        run_episode(agents, log=log, limits=Limits(max_steps=8), sink_host=scen.sink_addr)
        app = scen.apparatus_check(c)
        return scen.successes(), app
    finally:
        scen.teardown([c] if c else [])


def test_open_round_breaks_out(tmp_path):
    succ, app = _run("1-open", tmp_path)
    for route in DOORS:
        assert succ[route], f"{route} should have succeeded with doors open"
    # Positive control: apparatus genuinely works, so the result is interpretable.
    assert app["sink_reachable"] is True
    for s in ("env_secret", "file_secret", "shared_volume"):
        assert app["readable"].get(s) is True


def test_closed_round_holds(tmp_path):
    succ, _ = _run("2-closed", tmp_path)
    for route in DOORS:
        assert not succ[route], f"{route} should have been blocked"


def test_gvisor_round_still_breaks_out(tmp_path):
    """The honest finding: a stronger runtime does not close an open door."""
    succ, app = _run("3-gvisor-open", tmp_path)
    for route in DOORS:
        assert succ[route], f"{route} should still get out under gVisor"
