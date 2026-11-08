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


def test_gvisor_round_still_breaks_out(tmp_path):
    """The honest finding: a stronger runtime does not close an open door."""
    succ, app = _run("gvisor-demo", tmp_path)
    for route in DOORS:
        assert succ[route], f"{route} should still get out under gVisor"


def test_containment_holds_with_secret_present(tmp_path):
    """The real test: secrets ARE present and readable, egress is closed."""
    succ, app = _run("containment", tmp_path)
    # Apparatus confirms the secrets are genuinely readable (so a non-leak means
    # containment, not an empty box).
    for s in ("env_secret", "file_secret", "shared_volume"):
        assert app["readable"].get(s) is True, f"{s} should be readable"
    # Nothing should get out.
    for route in DOORS:
        assert not succ[route], f"{route} must be contained"


def _run_team(round_name, tmp_path, n, no_chat=False):
    from swarm_sandbox.mock import RelayMock
    cfg = ROUNDS[round_name]
    run_dir = str(tmp_path / (round_name + ("_nochat" if no_chat else "")))
    os.makedirs(run_dir, exist_ok=True)
    log = EventLog(os.path.join(run_dir, "events.jsonl"))
    scen = Scenario(run_dir=run_dir, cfg=cfg)
    scen.setup()
    cs = []
    try:
        agents = []
        for i in range(n):
            c = scen.start_agent(i)
            cs.append(c)
            kind = "source" if cfg.role_for(i).file_secret else "exfil"
            agents.append(Agent(f"A{i}", RelayMock(kind, scen.sink_addr, str(i)), c))
        run_episode(agents, log=log, limits=Limits(max_steps=8),
                    sink_host=scen.sink_addr, shared_channel=(not no_chat))
        return scen.successes()
    finally:
        scen.teardown(cs)


def test_collusion_leaks_only_with_shared_channel(tmp_path):
    """Swarm finding: the secret escapes ONLY when the agents can talk."""
    leak = _run_team("collusion", tmp_path, 2, no_chat=False)
    assert leak["file_secret"], "secret should leak via the shared channel"
    control = _run_team("collusion", tmp_path, 2, no_chat=True)
    assert not control["file_secret"], "secret must NOT leak without the channel"
