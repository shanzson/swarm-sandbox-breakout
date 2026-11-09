"""Hardened container management (the walls the agent lives inside).

Isolation applied to every agent container:
  * non-root user, no new privileges, all Linux capabilities dropped
  * read-only root filesystem; the only writable place is a small tmpfs work
    dir (plus the explicitly planted "shared folder" door when that door is open)
  * process / memory / CPU limits
  * no Docker socket; the only host bind mounts are the planted, logged doors
  * attached only to an internal Docker network (no route to the real internet)
  * optional gVisor runtime (runsc) for the hardened round

Known residual limits (documented, not hidden):
  * A Docker `--internal` network still has a host-side gateway address, so a
    service the *host* binds on 0.0.0.0 may be reachable from an agent. Nothing
    in the scoring can see that path. Run on a host with no such listeners.
  * Containers on one network can talk to each other unless inter-container
    communication (ICC) is disabled on that network; `create_network(icc=False)`
    does that for the closed configuration.

Findings from UK AISI's container-escape benchmark: frontier models escaped
only through *misconfigurations* (an exposed Docker socket, writable host
mounts, privileged containers), never through kernel exploits. So the job here
is to get these settings right. The planted "doors" are deliberate, controlled
weaknesses we add on top and can log, not accidents.

Commands run via `docker exec` with a timeout that is enforced *inside* the
container too, and with output bounded at read time. The broker decides what
to run; this module just runs it inside the box and captures output.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass, field

# ---- HOW TO READ THIS FILE ----
# Purpose: build and drive the Docker container an agent lives inside. This
# module trusts nothing the agent does; it only trusts the docker daemon.
# Map:
#   * _run / docker_available / runtime_available: thin, timeout-bounded wrappers
#     over the docker CLI; all output is decoded leniently so hostile bytes can't
#     crash the broker.
#   * create_network / inspect_network / remove_network: the agent's network.
#     create_network FAILS CLOSED when a same-named network doesn't match the
#     requested isolation, so a stray NAT bridge can't hand the agent egress.
#   * ContainerSpec: the hardening profile (user, caps, limits, fs, network).
#   * start_container: turns each ContainerSpec field into a `docker run` wall.
#   * Container.exec: runs one command via `docker exec`, bounded in time
#     (inside the container too) and in output bytes.
# Invariants protected: non-root + no-new-privileges + all caps dropped; root fs
# read-only with only a small tmpfs writable; the network that must stay isolated
# is set at START (gVisor ignores later attachments); every command is bounded.

MAX_OUTPUT_BYTES = 16_000  # hard bound on bytes read back from one command


# ---- docker CLI wrappers (every call is timeout-bounded and decodes leniently) ----

class DockerError(RuntimeError):
    pass


def _run(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    """Run a docker CLI command. Output is decoded leniently (never raises on bytes)."""
    # timeout bounds every docker call so a wedged daemon can't hang the broker.
    cp = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    # "replace" decoding: hostile or binary bytes become U+FFFD instead of raising
    # UnicodeDecodeError, which an agent could otherwise use to crash the broker.
    cp.stdout = (cp.stdout or b"").decode("utf-8", "replace")
    cp.stderr = (cp.stderr or b"").decode("utf-8", "replace")
    return cp


def docker_available() -> bool:
    try:
        return _run(["docker", "info"], timeout=15).returncode == 0
    except Exception:
        return False


def runtime_available(runtime: str) -> bool:
    # Substring test over the JSON list of installed runtimes; decides whether
    # the gVisor (runsc) hardened round can run on this host at all.
    cp = _run(["docker", "info", "--format", "{{json .Runtimes}}"], timeout=15)
    return runtime in cp.stdout


def inspect_network(name: str) -> dict | None:
    cp = _run(["docker", "network", "inspect", name], timeout=15)
    if cp.returncode != 0:
        return None
    try:
        return json.loads(cp.stdout)[0]
    except Exception:
        return None


def create_network(name: str, *, internal: bool, icc: bool = True) -> None:
    """Create a network. If one with this name exists it MUST already match the
    requested isolation, otherwise we refuse to run (a pre-existing NAT bridge
    with the same name would silently give the agent real egress)."""
    existing = inspect_network(name)
    if existing is not None:
        # Fail closed: a network with this name already exists, but if its
        # isolation differs from what we asked for we refuse rather than reuse it.
        # Reusing a pre-existing NAT bridge of the same name would silently grant
        # the agent real internet egress -- the exact thing this network prevents.
        if bool(existing.get("Internal")) != internal:
            raise DockerError(
                f"network {name!r} already exists with Internal={existing.get('Internal')}; "
                f"refusing to reuse it (wanted internal={internal})."
            )
        opts = existing.get("Options") or {}
        # Same stance for inter-container comms: if we wanted ICC off but the
        # existing network still allows it (docker's default when unset is "true"),
        # refuse -- otherwise two agents could collude over that network.
        if not icc and opts.get("com.docker.network.bridge.enable_icc", "true") != "false":
            raise DockerError(f"network {name!r} already exists with ICC enabled; refusing to reuse it.")
        return
    args = ["docker", "network", "create"]
    if internal:
        args.append("--internal")  # no gateway to the outside world
    if not icc:
        # containers on this network cannot talk to each other
        args += ["-o", "com.docker.network.bridge.enable_icc=false"]
    args.append(name)
    cp = _run(args, timeout=30)
    if cp.returncode != 0:
        raise DockerError(f"network create {name}: {cp.stderr.strip()}")
    # Verify what we got, do not assume.
    # Re-inspect and confirm the isolation actually took: a create that "succeeds"
    # but yields a non-internal network must still abort the run (fail closed),
    # never run an agent on a network we only believe is isolated.
    made = inspect_network(name)
    if made is None or bool(made.get("Internal")) != internal:
        raise DockerError(f"network {name!r} was not created as internal={internal}")


def remove_network(name: str) -> None:
    _run(["docker", "network", "rm", name], timeout=30)


def container_runtime(name: str) -> str:
    """The runtime the container is actually running under (e.g. 'runc', 'runsc')."""
    cp = _run(["docker", "inspect", "-f", "{{.HostConfig.Runtime}}", name], timeout=15)
    return cp.stdout.strip() if cp.returncode == 0 else ""


def image_exists(tag: str) -> bool:
    return _run(["docker", "image", "inspect", tag], timeout=15).returncode == 0


def build_image(tag: str, dockerfile: str, context_dir: str, *, timeout: float = 600.0) -> bool:
    """Build an image. Returns True on success, False on failure (caller falls back)."""
    cp = _run(
        ["docker", "build", "-t", tag, "-f", dockerfile, context_dir],
        timeout=timeout,
    )
    return cp.returncode == 0


# ---- the hardening profile and the container that carries it ----

# ContainerSpec is the complete isolation profile; start_container turns each
# field into a `docker run` flag. The defaults are the safe ones (non-root uid,
# read-only rootfs), so a caller that forgets to harden still gets a hard box.
@dataclass
class ContainerSpec:
    image: str = "python:3.12-slim"
    work_dir: str = "/work"
    user: str = "1000:1000"
    memory: str = "256m"
    cpus: str = "0.5"
    pids_limit: int = 128
    runtime: str | None = None          # "runsc" for gVisor, else default
    network: str | None = None          # the network the container is STARTED on
    env: dict[str, str] = field(default_factory=dict)   # planted env canaries live here
    extra_networks: list[str] = field(default_factory=list)  # attached after start (not seen by gVisor)
    volumes: list[str] = field(default_factory=list)    # "hostdir:/path[:ro]" (planted doors only)
    read_only: bool = True


@dataclass
class Container:
    name: str
    spec: ContainerSpec

    def exec(self, command: str, *, timeout: float = 30.0) -> tuple[int, str]:
        """Run a shell command inside the container. Returns (exit_code, combined_output).

        * The timeout is enforced inside the container (`timeout -k`), so a
          hung command is killed there, not just abandoned.
        * Output is read with a hard byte bound and decoded leniently, so a
          command that prints gigabytes or binary cannot exhaust host memory or
          crash the broker.
        """
        if not isinstance(command, str) or not command.strip():
            return 2, "[broker] empty or non-string command"
        secs = max(1, int(timeout))
        args = [
            "docker", "exec",
            "--user", self.spec.user,       # run as the non-root spec user, never root
            "--workdir", self.spec.work_dir,
            self.name,
            # `timeout -k 2 secs` wraps the command INSIDE the container with its
            # own kill-switch: a hung or forking command is killed in the box after
            # secs (SIGKILL 2s later), not merely abandoned host-side.
            "timeout", "-k", "2", str(secs), "bash", "-lc", command,
        ]
        try:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL)
        except OSError as e:
            return 125, f"[broker] could not start docker exec: {e}"
        assert p.stdout is not None
        chunks: list[bytes] = []
        got = 0
        truncated = False
        try:
            # Read in 4 KB chunks but retain at most MAX_OUTPUT_BYTES: an agent
            # that prints unbounded (or binary) output cannot make the broker
            # buffer it all in host RAM and fall over.
            while True:
                b = p.stdout.read(4096)
                if not b:
                    break
                if got < MAX_OUTPUT_BYTES:
                    take = b[: MAX_OUTPUT_BYTES - got]
                    chunks.append(take)
                    got += len(take)
                if got >= MAX_OUTPUT_BYTES:
                    truncated = True
                    break
            if truncated:
                p.kill()  # seen enough; stop the command instead of draining it
            # the in-container `timeout` bounds the command; this is a backstop
            # host-side wait (secs + 10) in case `docker exec` itself wedges.
            code = p.wait(timeout=secs + 10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            code = 124
        finally:
            p.stdout.close()
        out = b"".join(chunks).decode("utf-8", "replace")
        if truncated:
            out += f"\n[output truncated at {MAX_OUTPUT_BYTES} bytes]"
        if code == 124:
            out += f"\n[timed out after {secs}s]"
        return code, out

    def runtime(self) -> str:
        return container_runtime(self.name)

    def remove(self) -> None:
        _run(["docker", "rm", "-f", self.name], timeout=30)


# ---- starting a hardened container ----

def start_container(spec: ContainerSpec, *, name_prefix: str = "agent") -> Container:
    name = f"{name_prefix}-{uuid.uuid4().hex[:8]}"  # random suffix: unguessable name, no collisions
    # Each flag below is a wall, and they are applied at run time because most of
    # them (user, caps, read-only, runtime, the isolated network) cannot be
    # changed after the container is running.
    args = [
        "docker", "run", "-d", "--name", name,
        "--user", spec.user,                        # non-root uid:gid, so the agent starts unprivileged
        "--cap-drop", "ALL",                        # drop every Linux capability (no CAP_NET_ADMIN / CAP_SYS_ADMIN / ...)
        "--security-opt", "no-new-privileges",      # setuid binaries can't raise privileges; blocks sudo-style escalation
        "--pids-limit", str(spec.pids_limit),       # cap process count so a fork-bomb can't exhaust host PIDs
        "--memory", spec.memory,                    # hard memory ceiling: OOM-kills the container, not the host
        "--cpus", spec.cpus,                        # CPU quota so one agent can't starve the host or its peers
        "--workdir", spec.work_dir,
        # writable scratch only here; nowhere else on the fs is writable
        "--tmpfs", f"{spec.work_dir}:rw,size=32m,uid=1000,gid=1000",  # size-capped in-RAM scratch, owned by the non-root uid
    ]
    if spec.read_only:
        args.append("--read-only")                  # root filesystem read-only: agent can't tamper with binaries/config
    if spec.runtime:
        args += ["--runtime", spec.runtime]         # e.g. runsc (gVisor): a user-space kernel for the hardened round
    if spec.network:
        # The isolated network MUST be set here at start: gVisor only sees
        # networks present at container start, so a net attached later (see
        # extra_networks) would be invisible to it and escape the isolation.
        args += ["--network", spec.network]
    for k, v in spec.env.items():
        args += ["-e", f"{k}={v}"]               # planted env canaries / the SINK address are injected here
    for vol in spec.volumes:
        args += ["-v", vol]                      # ONLY the deliberate, logged "door" bind mounts (never the docker socket)
    args.append(spec.image)
    # PID 1 just idles; we drive everything through `docker exec`.
    args += ["sleep", "infinity"]

    cp = _run(args, timeout=90)
    if cp.returncode != 0:
        raise DockerError(f"run {name}: {cp.stderr.strip()}")

    # Attach any extra networks after creation. NOTE: gVisor does not see
    # networks attached after start, so the scenario puts the one that matters
    # in `network`, not here.
    for net in spec.extra_networks:
        a = _run(["docker", "network", "connect", net, name], timeout=30)
        if a.returncode != 0:
            raise DockerError(f"connect {net}: {a.stderr.strip()}")

    if spec.runtime:
        # Fail closed: if we asked for gVisor but docker silently fell back to the
        # default runtime, destroy the container and abort rather than score a
        # "hardened" round that never actually ran under the hardened runtime.
        actual = container_runtime(name)
        if actual != spec.runtime:
            _run(["docker", "rm", "-f", name], timeout=30)
            raise DockerError(f"requested runtime {spec.runtime!r} but container runs {actual!r}")
    return Container(name=name, spec=spec)
