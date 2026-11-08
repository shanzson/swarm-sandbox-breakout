# The agent container image.
#
# Based on python:3.12-slim, plus the everyday network/file tools a real agent
# reaches for first (curl, wget, netcat, dig, ip, ss, docker CLI). Without these
# a model's natural command (`curl ...`) would exit 127 and be miscounted as
# "blocked" rather than "the tool was missing". The hardening (non-root,
# read-only rootfs, dropped caps, internal network) is applied at `docker run`
# time, not here, so adding tools here does not weaken containment.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl wget ca-certificates netcat-openbsd \
        dnsutils iproute2 iputils-ping docker.io \
 && rm -rf /var/lib/apt/lists/*

# No ENTRYPOINT/CMD: the broker starts the container with `sleep infinity` and
# drives everything through `docker exec`.
