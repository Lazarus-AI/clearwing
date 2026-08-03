"""Shared Kubernetes client utilities for the sandbox backend.

Provides a cached API client and common helpers used by both
kube_sandbox.py (pod lifecycle) and kube_builder.py (Kaniko builds).
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_NAMESPACE_ENV = "CLEARWING_SANDBOX_NAMESPACE"

# Module-level cached client — initialized once on first use.
_api_client = None


def namespace() -> str:
    """Resolve the Kubernetes namespace for sandbox resources.

    Priority:
    1. CLEARWING_SANDBOX_NAMESPACE env var
    2. In-cluster service account namespace file
    3. "default"
    """
    ns = os.environ.get(_NAMESPACE_ENV)
    if ns:
        return ns
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
            return f.read().strip()
    except OSError:
        return "default"


def get_api_client():
    """Return a cached kubernetes ApiClient, loading config once.

    Tries in-cluster config first (running as a pod), falls back to
    kubeconfig (local development / CI).
    """
    global _api_client
    if _api_client is not None:
        return _api_client

    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    _api_client = client.ApiClient()
    return _api_client


def core_v1_api():
    """Return a CoreV1Api using the cached client."""
    from kubernetes import client

    return client.CoreV1Api(api_client=get_api_client())


def batch_v1_api():
    """Return a BatchV1Api using the cached client."""
    from kubernetes import client

    return client.BatchV1Api(api_client=get_api_client())


def parent_pod_owner_reference():
    """Build an ownerReference pointing to the current (parent) pod.

    Returns None if we can't determine the current pod identity (e.g.
    running outside a cluster, or HOSTNAME/pod UID not available).
    """
    from kubernetes import client

    hostname = os.environ.get("HOSTNAME")
    if not hostname:
        return None

    try:
        api = core_v1_api()
        ns = namespace()
        pod = api.read_namespaced_pod(hostname, ns)
        return client.V1OwnerReference(
            api_version="v1",
            kind="Pod",
            name=pod.metadata.name,
            uid=pod.metadata.uid,
            block_owner_deletion=False,
        )
    except Exception:
        logger.debug("Could not resolve parent pod owner reference", exc_info=True)
        return None
