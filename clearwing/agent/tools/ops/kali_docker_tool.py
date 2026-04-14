import platform

from langchain_core.tools import tool
from langgraph.types import interrupt

CONTAINER_NAME = "clearwing-kali"


@tool
def kali_setup() -> dict:
    """Start a Kali Linux Docker container for specialized security tools.

    Pulls kalilinux/kali-rolling if not present, starts a container, and
    returns the container ID. Reuses existing container if one is already running.

    Returns:
        Dict with keys: container_id, status, message.
    """
    import docker

    client = docker.from_env()

    # Check for existing container
    try:
        existing = client.containers.get(CONTAINER_NAME)
        if existing.status == "running":
            return {
                "container_id": existing.id,
                "status": "reused",
                "message": f"Reusing existing Kali container {existing.short_id}",
            }
        existing.start()
        return {
            "container_id": existing.id,
            "status": "restarted",
            "message": f"Restarted existing Kali container {existing.short_id}",
        }
    except docker.errors.NotFound:
        pass

    # Pull image if needed
    try:
        client.images.get("kalilinux/kali-rolling")
    except docker.errors.ImageNotFound:
        client.images.pull("kalilinux/kali-rolling")

    network_mode = "host" if platform.system() == "Linux" else "bridge"

    container = client.containers.run(
        "kalilinux/kali-rolling",
        command="sleep infinity",
        name=CONTAINER_NAME,
        network_mode=network_mode,
        detach=True,
        tty=True,
    )

    return {
        "container_id": container.id,
        "status": "created",
        "message": f"Started new Kali container {container.short_id}",
    }


@tool
def kali_execute(container_id: str, command: str) -> dict:
    """Execute a command inside the Kali Docker container. REQUIRES HUMAN APPROVAL.

    Args:
        container_id: Docker container ID.
        command: Shell command to execute.

    Returns:
        Dict with keys: exit_code, output.
    """
    approval = interrupt(f"Approve running in Kali container: {command}")
    if not approval:
        return {"exit_code": -1, "output": "Command denied by user"}

    import docker

    client = docker.from_env()
    container = client.containers.get(container_id)
    exit_code, output = container.exec_run(command, tty=True)
    return {
        "exit_code": exit_code,
        "output": output.decode("utf-8", errors="replace"),
    }


@tool
def kali_install_tool(container_id: str, package_name: str) -> dict:
    """Install a package in the Kali Docker container via apt-get.

    Args:
        container_id: Docker container ID.
        package_name: Debian package name to install (e.g. 'nmap', 'nikto').

    Returns:
        Dict with keys: exit_code, output.
    """
    import docker

    client = docker.from_env()
    container = client.containers.get(container_id)
    exit_code, output = container.exec_run(
        f"apt-get update -qq && apt-get install -y -qq {package_name}", tty=True
    )
    return {
        "exit_code": exit_code,
        "output": output.decode("utf-8", errors="replace"),
    }


@tool
def kali_cleanup(container_id: str) -> dict:
    """Stop and remove the Kali Docker container.

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
