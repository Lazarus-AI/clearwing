import logging
import os
import platform

from clearwing.agent.tooling import interrupt, tool

logger = logging.getLogger(__name__)

CONTAINER_NAME = "clearwing-kali"
DEFAULT_IMAGE = "kalilinux/kali-rolling"

# Environment overrides for BYOS (Bring Your Own Sandbox):
#   CLEARWING_SANDBOX_IMAGE  — custom Docker image (default: kalilinux/kali-rolling)
#   CLEARWING_SANDBOX_NAME   — container name to create/reuse
#   CLEARWING_SANDBOX_ID     — attach to an already-running container (skip setup)
_ENV_IMAGE = os.environ.get("CLEARWING_SANDBOX_IMAGE", DEFAULT_IMAGE)
_ENV_NAME = os.environ.get("CLEARWING_SANDBOX_NAME", CONTAINER_NAME)
_ENV_CONTAINER_ID = os.environ.get("CLEARWING_SANDBOX_ID", "")


def _detect_network() -> str | None:
    """Detect the Docker network this process's container is attached to.

    When clearwing itself runs inside a container (DinD via socket mount),
    we need to attach the Kali container to the same network so it can
    reach the target. Returns the network name or None for host mode.
    """
    import docker

    # If we're inside a container, /.dockerenv exists or /proc/1/cgroup mentions docker
    in_container = os.path.exists("/.dockerenv")
    if not in_container:
        try:
            with open("/proc/1/cgroup") as f:
                in_container = "docker" in f.read()
        except (FileNotFoundError, PermissionError):
            pass

    if not in_container:
        # Running on bare metal — use host on Linux, bridge on macOS
        return "host" if platform.system() == "Linux" else None

    # We're inside a container — find our network by inspecting our own container
    hostname = os.environ.get("HOSTNAME", "")
    if not hostname:
        return None

    client = docker.from_env()
    try:
        self_container = client.containers.get(hostname)
        networks = self_container.attrs.get("NetworkSettings", {}).get("Networks", {})
        # Prefer non-default networks (compose creates project-scoped ones)
        for name in networks:
            if name != "bridge":
                logger.debug("Detected container network: %s", name)
                return name
        # Fall back to whatever we're on
        if networks:
            name = next(iter(networks))
            logger.debug("Falling back to container network: %s", name)
            return name
    except Exception as exc:
        logger.debug("Could not detect container network: %s", exc)

    return None


@tool
def kali_setup(image: str = "", container_name: str = "", container_id: str = "") -> dict:
    """Start or attach to a Docker container for security tool execution.

    Supports three modes:
      1. Pre-existing container (BYOS): pass container_id or set CLEARWING_SANDBOX_ID
         to attach to an already-running container — skips image pull/creation entirely.
      2. Custom image: pass image or set CLEARWING_SANDBOX_IMAGE to use your own
         pre-built image instead of kalilinux/kali-rolling.
      3. Default: pulls and starts kalilinux/kali-rolling.

    Environment variables (override defaults without changing tool calls):
      - CLEARWING_SANDBOX_IMAGE: Docker image to use
      - CLEARWING_SANDBOX_NAME: Container name to create/reuse
      - CLEARWING_SANDBOX_ID: Attach to this container ID directly (skip setup)

    Args:
        image: Docker image to use (default: kalilinux/kali-rolling or CLEARWING_SANDBOX_IMAGE).
        container_name: Name for the container (default: clearwing-kali or CLEARWING_SANDBOX_NAME).
        container_id: Attach to an existing running container by ID (skips creation).

    Returns:
        Dict with keys: container_id, status, message.
    """
    import docker

    client = docker.from_env()
    image = image or _ENV_IMAGE
    container_name = container_name or _ENV_NAME
    attach_id = container_id or _ENV_CONTAINER_ID

    # Mode 1: attach to pre-existing container
    if attach_id:
        try:
            existing = client.containers.get(attach_id)
            if existing.status != "running":
                existing.start()
            return {
                "container_id": existing.id,
                "status": "attached",
                "message": f"Attached to existing container {existing.short_id} ({existing.image.tags[0] if existing.image.tags else 'unknown'})",
            }
        except Exception as exc:
            return {
                "container_id": "",
                "status": "error",
                "message": f"Cannot attach to container {attach_id[:12]}: {exc}",
            }

    # Mode 2/3: create or reuse a named container
    try:
        existing = client.containers.get(container_name)
        if existing.status == "running":
            return {
                "container_id": existing.id,
                "status": "reused",
                "message": f"Reusing existing container {existing.short_id} ({image})",
            }
        existing.start()
        return {
            "container_id": existing.id,
            "status": "restarted",
            "message": f"Restarted existing container {existing.short_id} ({image})",
        }
    except docker.errors.NotFound:
        pass

    # Pull image if needed
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        logger.info("Pulling image %s ...", image)
        client.images.pull(image)

    detected_network = _detect_network()

    # network_mode="host" vs joining a named network are mutually exclusive
    run_kwargs: dict = {}
    if detected_network == "host":
        run_kwargs["network_mode"] = "host"
    elif detected_network:
        run_kwargs["network"] = detected_network
    # else: default bridge

    container = client.containers.run(
        image,
        command="sleep infinity",
        name=container_name,
        detach=True,
        tty=True,
        **run_kwargs,
    )

    net_info = detected_network or "default bridge"
    return {
        "container_id": container.id,
        "status": "created",
        "message": f"Started new container {container.short_id} (image: {image}, network: {net_info})",
    }


@tool
def kali_execute(container_id: str, command: str) -> dict:
    """Execute a command inside the sandbox Docker container. REQUIRES HUMAN APPROVAL.

    Streams output to the event bus in real-time (visible with -v flag).

    Args:
        container_id: Docker container ID.
        command: Shell command to execute.

    Returns:
        Dict with keys: exit_code, output.
    """
    approval = interrupt(f"Approve running in sandbox container: {command}")
    if not approval:
        return {"exit_code": -1, "output": "Command denied by user"}

    import docker

    from clearwing.core.events import EventBus

    client = docker.from_env()
    container = client.containers.get(container_id)
    bus = EventBus()

    exec_resp = container.client.api.exec_create(container.id, command, tty=True)
    output_stream = container.client.api.exec_start(exec_resp["Id"], stream=True)

    chunks = []
    for chunk in output_stream:
        text = chunk.decode("utf-8", errors="replace")
        chunks.append(text)
        for line in text.splitlines():
            if line.strip():
                bus.emit_message(f"[sandbox] {line.rstrip()}", "debug")

    exec_info = container.client.api.exec_inspect(exec_resp["Id"])
    exit_code = exec_info.get("ExitCode", -1)

    return {
        "exit_code": exit_code,
        "output": "".join(chunks),
    }


@tool
def kali_install_tool(container_id: str, package_name: str) -> dict:
    """Install a package in the sandbox Docker container via apt-get.

    Args:
        container_id: Docker container ID.
        package_name: Debian package name to install (e.g. 'nmap', 'nikto').

    Returns:
        Dict with keys: exit_code, output.
    """
    import docker

    client = docker.from_env()
    container = client.containers.get(container_id)
    # Must wrap in sh -c for compound commands; avoid tty=True which
    # causes argument-splitting issues in some Docker API versions.
    cmd = ["sh", "-c", f"apt-get update -qq && apt-get install -y -qq {package_name}"]
    exit_code, output = container.exec_run(cmd)
    return {
        "exit_code": exit_code,
        "output": output.decode("utf-8", errors="replace"),
    }


@tool
def kali_cleanup(container_id: str) -> dict:
    """Stop and remove the sandbox Docker container.

    Args:
        container_id: Docker container ID.

    Returns:
        Dict with keys: status, message.
    """
    import docker

    client = docker.from_env()
    try:
        container = client.containers.get(container_id)
        container.stop(timeout=5)
        container.remove()
        return {"status": "removed", "message": f"Container {container_id[:12]} removed"}
    except docker.errors.NotFound:
        return {"status": "not_found", "message": "Container not found"}
