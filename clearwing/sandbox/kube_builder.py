"""On-cluster image building via Kaniko for Kubernetes sandbox backend.

When CLEARWING_SANDBOX_BACKEND=kubernetes, sandbox images can't be built via
the local Docker daemon (there isn't one). Instead we submit a Kaniko Job that
builds + pushes the image to the cluster's registry.

Environment variables:
  CLEARWING_SANDBOX_REGISTRY — required registry prefix (e.g. "ghcr.io/org/clearwing-sandbox")
  CLEARWING_KANIKO_IMAGE — kaniko executor image (default: gcr.io/kaniko-project/executor:latest)
  CLEARWING_KANIKO_SERVICE_ACCOUNT — SA for build jobs (default: "default")
"""

from __future__ import annotations

import hashlib
import logging
import os
import time

from .kube_client import batch_v1_api, core_v1_api, namespace

logger = logging.getLogger(__name__)

_REGISTRY_ENV = "CLEARWING_SANDBOX_REGISTRY"
_KANIKO_IMAGE_ENV = "CLEARWING_KANIKO_IMAGE"
_KANIKO_SA_ENV = "CLEARWING_KANIKO_SERVICE_ACCOUNT"

_DEFAULT_KANIKO_IMAGE = "gcr.io/kaniko-project/executor:latest"
_DEFAULT_SA = "default"
_BUILD_TIMEOUT_SECONDS = 600
_POLL_INTERVAL_SECONDS = 5


def _registry() -> str:
    registry = os.environ.get(_REGISTRY_ENV, "")
    if not registry:
        raise RuntimeError(
            f"{_REGISTRY_ENV} must be set when using Kubernetes sandbox backend "
            "without CLEARWING_SANDBOX_IMAGE override"
        )
    return registry.rstrip("/")


def compute_registry_tag(
    dockerfile: str,
    sanitizers: list[str],
    extra_packages: list[str],
    post_install_commands: list[str],
) -> str:
    """Compute a deterministic registry image tag from content hash.

    Same hashing logic as HunterSandbox._compute_tag but prefixed with the
    configured registry so it's a fully qualified image reference.
    """
    h = hashlib.sha256()
    h.update(dockerfile.encode("utf-8"))
    h.update(",".join(sorted(sanitizers)).encode("utf-8"))
    h.update(",".join(sorted(extra_packages)).encode("utf-8"))
    h.update("\n".join(post_install_commands).encode("utf-8"))
    digest = h.hexdigest()[:12]
    return f"{_registry()}:{digest}"


def image_exists_in_registry(image_tag: str) -> bool:
    """Check if the image tag already exists in the registry.

    Tries `crane manifest` first (fast, no k8s API needed). Falls back to
    assuming the image doesn't exist (triggering a rebuild) when crane is
    not available.
    """
    try:
        import subprocess

        result = subprocess.run(
            ["crane", "manifest", image_tag],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    logger.debug("crane not available; assuming image %s needs building", image_tag)
    return False


def build_image_on_cluster(dockerfile_content: str, image_tag: str) -> str:
    """Submit a Kaniko Job to build and push the image on-cluster.

    Creates a ConfigMap with the Dockerfile, then a Job that mounts it and
    runs Kaniko to build + push to the registry. Blocks until the Job
    completes or times out.

    Returns the image_tag on success; raises RuntimeError on failure.
    """
    from kubernetes import client

    ns = namespace()
    kaniko_image = os.environ.get(_KANIKO_IMAGE_ENV, _DEFAULT_KANIKO_IMAGE)
    service_account = os.environ.get(_KANIKO_SA_ENV, _DEFAULT_SA)

    # Unique name for this build
    tag_hash = image_tag.rsplit(":", 1)[-1] if ":" in image_tag else "build"
    job_name = f"clearwing-build-{tag_hash}"
    configmap_name = f"clearwing-dockerfile-{tag_hash}"

    core = core_v1_api()
    batch = batch_v1_api()

    # Create ConfigMap with the Dockerfile
    configmap = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(
            name=configmap_name,
            namespace=ns,
            labels={"managed-by": "clearwing", "purpose": "sandbox-build"},
        ),
        data={"Dockerfile": dockerfile_content},
    )
    try:
        core.create_namespaced_config_map(ns, configmap)
    except client.ApiException as e:
        if e.status == 409:
            core.replace_namespaced_config_map(configmap_name, ns, configmap)
        else:
            raise

    # Build the Kaniko Job
    job = client.V1Job(
        metadata=client.V1ObjectMeta(
            name=job_name,
            namespace=ns,
            labels={"managed-by": "clearwing", "purpose": "sandbox-build"},
        ),
        spec=client.V1JobSpec(
            ttl_seconds_after_finished=300,
            backoff_limit=0,
            active_deadline_seconds=_BUILD_TIMEOUT_SECONDS,
            template=client.V1PodTemplateSpec(
                spec=client.V1PodSpec(
                    service_account_name=service_account,
                    restart_policy="Never",
                    containers=[
                        client.V1Container(
                            name="kaniko",
                            image=kaniko_image,
                            args=[
                                "--dockerfile=/workspace/Dockerfile",
                                "--context=dir:///workspace",
                                f"--destination={image_tag}",
                                "--cache=true",
                                "--single-snapshot",
                            ],
                            volume_mounts=[
                                client.V1VolumeMount(
                                    name="dockerfile",
                                    mount_path="/workspace",
                                    read_only=True,
                                ),
                            ],
                        ),
                    ],
                    volumes=[
                        client.V1Volume(
                            name="dockerfile",
                            config_map=client.V1ConfigMapVolumeSource(
                                name=configmap_name,
                            ),
                        ),
                    ],
                ),
            ),
        ),
    )

    try:
        batch.create_namespaced_job(ns, job)
    except client.ApiException as e:
        if e.status == 409:
            # Job already exists — delete and recreate
            batch.delete_namespaced_job(
                job_name, ns, propagation_policy="Background"
            )
            time.sleep(2)
            batch.create_namespaced_job(ns, job)
        else:
            raise

    # Poll until completion
    logger.info("Waiting for Kaniko build job %s/%s", ns, job_name)
    deadline = time.monotonic() + _BUILD_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        status = batch.read_namespaced_job_status(job_name, ns).status
        if status.succeeded and status.succeeded > 0:
            logger.info("Kaniko build succeeded: %s", image_tag)
            _cleanup_build_resources(core, batch, ns, job_name, configmap_name)
            return image_tag
        if status.failed and status.failed > 0:
            logs = _get_build_logs(core, ns, job_name)
            _cleanup_build_resources(core, batch, ns, job_name, configmap_name)
            raise RuntimeError(
                f"Kaniko build failed for {image_tag}. Logs:\n{logs[-2000:]}"
            )
        time.sleep(_POLL_INTERVAL_SECONDS)

    _cleanup_build_resources(core, batch, ns, job_name, configmap_name)
    raise RuntimeError(
        f"Kaniko build timed out after {_BUILD_TIMEOUT_SECONDS}s for {image_tag}"
    )


def _get_build_logs(core, ns: str, job_name: str) -> str:
    """Best-effort retrieval of build pod logs."""
    try:
        pods = core.list_namespaced_pod(ns, label_selector=f"job-name={job_name}")
        if pods.items:
            return core.read_namespaced_pod_log(
                pods.items[0].metadata.name, ns, container="kaniko"
            )
    except Exception:
        pass
    return "(logs unavailable)"


def _cleanup_build_resources(core, batch, ns: str, job_name: str, configmap_name: str) -> None:
    """Best-effort cleanup of build Job and ConfigMap."""
    try:
        batch.delete_namespaced_job(job_name, ns, propagation_policy="Background")
    except Exception:
        pass
    try:
        core.delete_namespaced_config_map(configmap_name, ns)
    except Exception:
        pass
