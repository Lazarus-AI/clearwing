"""Docker-in-Docker rootless client factory.

Resolves the Docker daemon endpoint in priority order:
  1. CLEARWING_DOCKER_HOST env var (K8s sidecar / explicit override)
  2. DOCKER_HOST env var (standard Docker convention)
  3. /var/run/docker.sock (local dev default)

This lets the sandbox module work unchanged whether talking to:
  - A host Docker daemon (local dev)
  - A rootless DinD sidecar (K8s deployment)
  - A remote daemon (CI runners)

The subprocess-based build calls in HunterSandbox also need the resolved
host — use `get_docker_host()` to get the URI string and pass it via env.
"""

from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)

_DEFAULT_SOCKET = "/var/run/docker.sock"
_ROOTLESS_SOCKET = "/run/user/1000/docker.sock"

# Env var specific to Clearwing — takes priority over DOCKER_HOST so
# operators can run clearwing inside a container that itself has a
# DOCKER_HOST pointing at the host daemon, while clearwing's sandboxes
# go to the rootless sidecar.
_CLEARWING_ENV = "CLEARWING_DOCKER_HOST"


def get_docker_host() -> str | None:
    """Resolve the Docker daemon URI string.

    Returns None when the default socket is used (docker-py's from_env()
    handles that case). Returns a URI string otherwise.
    """
    # Explicit clearwing override
    cw_host = os.environ.get(_CLEARWING_ENV, "").strip()
    if cw_host:
        return cw_host

    # Standard DOCKER_HOST
    dh = os.environ.get("DOCKER_HOST", "").strip()
    if dh:
        return dh

    # Rootless user socket (common in rootless Docker installs)
    if os.path.exists(_ROOTLESS_SOCKET):
        return f"unix://{_ROOTLESS_SOCKET}"

    # Default socket — return None to let docker-py use its default
    if os.path.exists(_DEFAULT_SOCKET):
        return None

    # Nothing found — return None and let docker-py raise on connect
    return None


def get_docker_client(timeout: int = 60):
    """Return a connected docker.DockerClient for the resolved daemon.

    Waits up to `timeout` seconds for the daemon to become responsive
    (useful when the DinD sidecar is still starting).
    """
    import docker

    host = get_docker_host()
    if host:
        logger.debug("Connecting to Docker daemon at %s", host)
        client = docker.DockerClient(base_url=host)
    else:
        client = docker.from_env()

    # Health-check with retry — DinD sidecars take a moment to start
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            client.ping()
            return client
        except Exception as e:
            last_err = e
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(1.0, remaining))

    # If we exhausted the timeout, still return the client — the caller
    # will get a clear error on their first API call. Log a warning.
    if last_err:
        logger.warning(
            "Docker daemon at %s not responsive after %ds: %s",
            host or "default socket",
            timeout,
            last_err,
        )
    return client


def get_subprocess_env() -> dict[str, str]:
    """Return an env dict suitable for subprocess.run(env=...) that routes
    docker CLI commands to the resolved daemon.

    Merges with os.environ so PATH etc. are preserved.
    """
    env = dict(os.environ)
    host = get_docker_host()
    if host:
        env["DOCKER_HOST"] = host
    return env
