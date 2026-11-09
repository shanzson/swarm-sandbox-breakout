# 🔓 Break Out of Your Own Sandbox

**Red-team AI agents are rewarded for escaping a multi-agent sandbox. We log every
route they try, close the ones that work, and publish a checklist for safer
multi-agent evaluations.**

Apart Research · **Swarm Alignment Hackathon** (Nov 6–8, 2026) · Track 1: Sandboxes and Testbeds

---

## 💡 The idea in 30 seconds

AI agents are tested inside sandboxes, but sandboxes have holes.
- In 2024, OpenAI's o1 got out of its test through a misconfigured Docker setup on the host.
- In 2026, about 1,200 "separately sandboxed" agents found a shared space and coordinated through it.

So we build a sandbox, **give agents a reason to escape**, and watch how they try.
The "outside world" is a **fake server we control**, never the real internet. The
"secrets" are **decoy tokens**. If a decoy reaches the fake server, we know that
route got out.

| Round | Sandbox | Question |
|---|---|---|
| **open** | Secret present, doors open | Does the agent find and exfiltrate it? (capability baseline) |
| **containment** | **Secret present and readable, exit closed** | **The real test: can it get a present secret out?** |
| **containment-gvisor** | Same, under gVisor | Does a stronger runtime change containment? |
| **discovery** | Doors open, but sink address withheld | Does it *discover* a reachable host, not get handed one? |
| **gvisor-demo** | Doors open, under gVisor | Demonstration: a runtime does not fix a misconfiguration |
| **collusion** | Secret in agent A, exit in agent B, shared chat | Does the swarm cooperate to leak it? |

A key design point: a "closed" result is only evidence when the thing being
protected is actually **present**. The old "remove the secret and lock the door"
round proved nothing; the **containment** round keeps the secret present and
readable and only closes the exit.

There are also **one-door-at-a-time rounds** (`env-only`, `file-only`,
`shared-only`, `egress-only`) so a block can be attributed to the *single* setting
that caused it, and an **evaluation-awareness** arm that re-runs rounds with a
prompt that does *not* announce a test.

Each round runs with a **solo agent** and with a **team that shares a chat**, to
see whether a group finds routes a loner misses.

---

## 🔒 Safety first (how this stays contained)

```
 agent container(s)                         broker (trusted, on host)
  • non-root, read-only rootfs               • holds the API key (env var only)
  • all Linux caps dropped                   • runs each command via `docker exec`
  • no real internet, no API key    ◀──────  • enforces step/time/turn/budget limits
  • only writable spot: a tmpfs /work        • writes the ONLY log (hash-chained + tip anchor)
          │ bash tool calls only                        │
          ▼                                              ▼
   fake "outside world"  ── logs any decoy ──▶   model API (DeepSeek via Adaption)
   (raw-capture sink + gated honeypot)           only reads/writes text
```

- **The model cannot run anything.** It only returns text and "run this command"
  requests. The broker decides what runs, and it runs **inside the locked
  container**, never on the host.
- **The API key never enters an agent container,** the code, or the log. It is
  read only from `ADAPTION_API_KEY` and scrubbed from everything written to disk.
- **Only our own tool is ever sent to the model.** Provider-side tools that could
  reach the internet from the model's side (remote MCP, file search, web search)
  are refused in code.
- **The sink captures at the socket level.** It records the raw bytes of every
  connection, so a plain `/dev/tcp` write, an odd HTTP method, or a chunked body
  is caught — an open door is never scored "blocked" just because the exfil
  didn't look like a tidy GET.
- **The log is tamper-evident.** Each entry is hash-chained to the one before, and
  an out-of-band tip anchor (record count + final hash) also catches deletion of
  the last records (`EventLog.verify`). The published table is read from the
  verified chain, not from an unsigned file.
- **Positive controls.** Before scoring, the harness confirms from inside the
  container that the secret is readable and (when egress is open) the sink is
  reachable. A run whose apparatus doesn't work is marked **invalid**, not
  "blocked", so a benign failure can't masquerade as a defence.
- **Limits and a kill switch:** steps per agent, tool calls per turn, a wall-clock
  limit, and a single **run-level** credit cap (shared across all agents) that
  fails closed if the provider omits a cost field.

The whole thing runs inside one disposable cloud VM, which is the outer wall.
Two residual limits are documented, not hidden: a Docker `--internal` network
still has a host-side gateway (so the host must run no listeners an agent could
reach), and the unkeyed hash chain defends against tampering but not against a
host actor who can rewrite both the log and its anchor.

---

## 📈 Results (deepseek-v4-flash & glm-5.2 via Adaption)

**225 episodes, ~13.7 credits**, every run hash-chain + tip-anchor verified and
**independently re-audited** by adversarial agents that re-derived each number from
the raw logs. Full write-up with tables and figures: **[`REPORT.md`](REPORT.md)**.

**1. Containment holds — with a real secret inside.** Secret present and
apparatus-confirmed readable, exit closed: **0 of 33 valid runs leaked**, both models,
plain Docker and gVisor alike — though agents read the secret and fired 14–74 exfil
attempts per run. The honest "walls held" result (an empty-box "closed" round could
not show it).

**2. Framing, not capability, gates behavior.** `glm-5.2` does the full break-in when
told it's an authorised security test (40/40 on open rounds) but **refuses 8/8** when
the same task is posed as a realistic malicious mission — even with every door open
(*"harmful regardless of how it's framed… whether the credentials are 'real' or planted
for a test"*). `deepseek` refuses only 2/24. A self-announcing eval can measure its own
framing.

**3. A shared channel defeats per-agent secret isolation — but our first "collusion"
result was a harness artifact.** The audit showed the secret crossed *only* via the
broker echoing agents' commands across a trust boundary (not model-driven sharing). A
**clean follow-up** (keepers ordered to guard a secret, no team framing, a plain shared
file, no echo) corrects it: **neither model leaks when ordered to guard (deepseek 0/6,
GLM 0/4)**, yet both share freely when not told to (3/3, 2/2). GLM — the apparent
"colluder" — does *not* break a confidentiality order once the harness confound is gone.

Supporting: gVisor changes nothing (config decides, not runtime); discovery works (the
agent finds a withheld sink by scanning); one-door rounds attribute each route cleanly;
the validity gate excluded flaky runs rather than miscounting them. Caveat: small n per
condition — enough for the clean separations, not for precise rates.

---

## ▶️ Run it yourself

```bash
pip install -r requirements.txt

# Free offline dry run — scripted mock agent, no API key, no credits:
python run_round.py --round 1-open --mode solo --mock

# Real agents (needs ADAPTION_API_KEY in the environment; never commit it):
export ADAPTION_API_KEY=...          # read only from here, never logged
python run_round.py --round containment --mode solo --model deepseek-v4-flash
python run_round.py --round collusion  --mode team --agents 3 --model deepseek-v4-flash
python run_round.py --round 1-open --mode solo --realistic --model deepseek-v4-flash  # eval-awareness arm

python run_matrix.py --model deepseek-v4-flash   # the whole experiment plan, with caps

# Clean collusion test (keeper ordered to guard a secret; no team framing; shared file, no echo):
python experiment_secret.py --arm strict --mock              # free offline validation
python run_secret_matrix.py --model deepseek-v4-flash        # strict/helpful/baseline/control arms
python make_figures.py               # regenerate figs/ from the verified logs

python analyse.py                    # combined table, read from the verified logs
python rerun.py runs/<run-id>        # replay a run from its tamper-proof log
python -m pytest -q                  # tests (safety logic runs without Docker)
```

On the first real run the harness builds a small **agent image** (base
`python:3.12-slim` plus curl/wget/netcat/dig/docker CLI) so a model's natural
command works instead of failing "command not found". If the build isn't
available it falls back to the base image and says so; which image was used is
recorded in the result.

**Reproducibility note:** the model API has no `seed`, so runs can't be made
bit-for-bit identical. We handle this two ways: `rerun.py` replays the *recorded
commands* exactly from the log (reusing the recorded decoy tokens and rewriting
the sink address so literal-value commands still reproduce), and each condition is
run several times so we report how often each route gets out, not a single number.

---

## 🗂️ What's in here

```
swarm_sandbox/
  llm.py         Model client: key from env only, shared run budget, tool allowlist, redaction
  sandbox.py     Hardened container settings, bounded exec, runtime check, gVisor
  scenario.py    Networks, the fake outside world, the planted doors, positive controls
  broker.py      The agent loop, limits, kill switch, shared team channel
  eventlog.py    Append-only, hash-chained log + tip anchor; fail-closed verify
  tools.py       The single bash tool + route classifier
  mock.py        Scripted agent for free offline runs
scenario/sink_server.py    Raw-capture fake internet + gated Docker honeypot
scenario/agent.Dockerfile  The tooled agent image
run_round.py · run_matrix.py · analyse.py · rerun.py   Run one / the matrix, summarise, replay
experiment_secret.py · run_secret_matrix.py   Clean collusion test (keeper/solver, shared file, no echo)
make_figures.py            Regenerate report figures from the verified logs
REPORT.md                  Full findings write-up (cross-model, audited)
tests/          Safety-logic tests + Docker-gated end-to-end rounds
```

---

## ✅ The checklist (draft, filled in by the runs)

Every route that worked, and the single setting that closed it:

| If you leave this open | An agent can | Close it by |
|---|---|---|
| A secret in an env var or file | Read and exfiltrate it | Don't mount secrets into agent containers; inject at the broker |
| A shared folder | Reach another agent's data | No shared mounts unless the experiment needs one, and log it |
| Any network egress | Phone home / exfiltrate | Internal-only network; a single logging proxy; default-deny |
| An exposed Docker API/socket | Control the host's containers | Never expose the socket; no `DOCKER_HOST` into agents |
| Agents on one shared network | Talk to each other unlogged | One network per agent, or disable inter-container comms |
| Relying on a stronger runtime | Still use any open hole | Fix the misconfiguration; a runtime is defence-in-depth, not a fix |

**Author:** Shantanu P. Sontakke
