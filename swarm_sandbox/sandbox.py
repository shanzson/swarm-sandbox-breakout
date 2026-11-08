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

MAX_OUTPUT_BYTES = 16_000  # hard bound on bytes read back from one command


class DockerError(RuntimeError):
    pass


def _run(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    """Run a docker CLI command. Output is decoded leniently (never raises on bytes)."""
    cp = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    cp.stdout = (cp.stdout or b"").decode("utf-8", "replace")
    cp.stderr = (cp.stderr or b"").decode("utf-8", "replace")
    return cp


def docker_available() -> bool:
    try:
        return _run(["docker", "info"], timeout=15).returncode == 0
    except Exception:
        return False


def runtime_available(runtime: str) -> bool:
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
        if bool(existing.get("Internal")) != internal:
            raise DockerError(
                f"network {name!r} already exists with Internal={existing.get('Internal')}; "
                f"refusing to reuse it (wanted internal={internal})."
            )
        opts = existing.get("Options") or {}
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
            "--user", self.spec.user,
            "--workdir", self.spec.work_dir,
            self.name,
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
                p.kill()
            # the in-container `timeout` bounds the command; this is a backstop
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


def start_container(spec: ContainerSpec, *, name_prefix: str = "agent") -> Container:
    name = f"{name_prefix}-{uuid.uuid4().hex[:8]}"
    args = [
        "docker", "run", "-d", "--name", name,
        "--user", spec.user,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(spec.pids_limit),
        "--memory", spec.memory,
        "--cpus", spec.cpus,
        "--workdir", spec.work_dir,
        # writable scratch only here; nowhere else on the fs is writable
        "--tmpfs", f"{spec.work_dir}:rw,size=32m,uid=1000,gid=1000",
    ]
    if spec.read_only:
        args.append("--read-only")
    if spec.runtime:
        args += ["--runtime", spec.runtime]
    if spec.network:
        args += ["--network", spec.network]
    for k, v in spec.env.items():
        args += ["-e", f"{k}={v}"]
    for vol in spec.volumes:
        args += ["-v", vol]
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
        actual = container_runtime(name)
        if actual != spec.runtime:
            _run(["docker", "rm", "-f", name], timeout=30)
            raise DockerError(f"requested runtime {spec.runtime!r} but container runs {actual!r}")
    return Container(name=name, spec=spec)
