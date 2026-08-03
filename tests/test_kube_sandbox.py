"""Unit tests for Kubernetes sandbox backend support."""

import os
import unittest
from unittest.mock import MagicMock, patch

from clearwing.sandbox.container import SandboxConfig
from clearwing.sandbox.factory import create_sandbox, is_kubernetes_backend


class IsKubernetesBackendTests(unittest.TestCase):
    def test_default_is_docker(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("CLEARWING_SANDBOX_BACKEND", None)
            self.assertFalse(is_kubernetes_backend())

    def test_explicit_docker(self):
        with patch.dict(os.environ, {"CLEARWING_SANDBOX_BACKEND": "docker"}):
            self.assertFalse(is_kubernetes_backend())

    def test_kubernetes_detected(self):
        with patch.dict(os.environ, {"CLEARWING_SANDBOX_BACKEND": "kubernetes"}):
            self.assertTrue(is_kubernetes_backend())

    def test_case_insensitive(self):
        with patch.dict(os.environ, {"CLEARWING_SANDBOX_BACKEND": "Kubernetes"}):
            self.assertTrue(is_kubernetes_backend())


class CreateSandboxFactoryTests(unittest.TestCase):
    def test_docker_backend_returns_sandbox_container(self):
        from clearwing.sandbox.container import SandboxContainer

        with patch.dict(os.environ, {"CLEARWING_SANDBOX_BACKEND": "docker"}):
            cfg = SandboxConfig(image="test:latest")
            # Don't actually start it — just verify the type
            with patch.object(SandboxContainer, "start"):
                sb = create_sandbox(cfg)
                self.assertIsInstance(sb, SandboxContainer)

    def test_kubernetes_backend_returns_kube_container(self):
        from clearwing.sandbox.kube_sandbox import KubeSandboxContainer

        with patch.dict(os.environ, {"CLEARWING_SANDBOX_BACKEND": "kubernetes"}):
            cfg = SandboxConfig(image="test:latest")
            sb = create_sandbox(cfg)
            self.assertIsInstance(sb, KubeSandboxContainer)


class HunterSandboxKubeImageResolutionTests(unittest.TestCase):
    """Test the k8s image resolution paths in HunterSandbox."""

    @patch.dict(os.environ, {
        "CLEARWING_SANDBOX_BACKEND": "kubernetes",
        "CLEARWING_SANDBOX_IMAGE": "registry.example/sandbox:override",
    })
    def test_override_image_used_for_all_variants(self):
        from clearwing.sandbox.hunter_sandbox import HunterSandbox

        with patch.object(HunterSandbox, "__init__", lambda self, **kw: None):
            sandbox = HunterSandbox.__new__(HunterSandbox)
            sandbox.sanitizers = ["asan", "ubsan"]
            sandbox.extra_variants = [["msan"]]
            sandbox.extra_packages = []
            sandbox.post_install_commands = []
            sandbox._variant_images = {}
            sandbox._image_tag = None

            tag = sandbox._resolve_kube_images()

            self.assertEqual(tag, "registry.example/sandbox:override")
            self.assertEqual(sandbox._image_tag, "registry.example/sandbox:override")
            # All variants should map to the override image
            for key, img in sandbox._variant_images.items():
                self.assertEqual(img, "registry.example/sandbox:override")

    @patch.dict(os.environ, {
        "CLEARWING_SANDBOX_BACKEND": "kubernetes",
        "CLEARWING_SANDBOX_REGISTRY": "ghcr.io/org/clearwing-sandbox",
    })
    @patch("clearwing.sandbox.hunter_sandbox.HunterSandbox._kaniko_build_if_needed")
    def test_registry_builds_via_kaniko(self, mock_build):
        from clearwing.sandbox.hunter_sandbox import HunterSandbox

        mock_build.side_effect = lambda df, tag: tag

        with patch.object(HunterSandbox, "__init__", lambda self, **kw: None):
            sandbox = HunterSandbox.__new__(HunterSandbox)
            sandbox.sanitizers = ["asan", "ubsan"]
            sandbox.extra_variants = []
            sandbox.extra_packages = ["python3"]
            sandbox.post_install_commands = []
            sandbox._variant_images = {}
            sandbox._image_tag = None
            sandbox.build_recipe = MagicMock()
            sandbox.build_recipe.base_image = "debian:11-slim"
            sandbox.build_recipe.apt_packages = ["build-essential"]
            sandbox._optional_packages = []

            # Need _render_dockerfile to work
            with patch.object(sandbox, "_render_dockerfile", return_value="FROM debian:11\n"):
                # Pop the CLEARWING_SANDBOX_IMAGE to avoid override path
                os.environ.pop("CLEARWING_SANDBOX_IMAGE", None)
                tag = sandbox._resolve_kube_images()

            self.assertTrue(tag.startswith("ghcr.io/org/clearwing-sandbox:"))
            self.assertEqual(mock_build.call_count, 1)


class KubeBuilderTagTests(unittest.TestCase):
    """Test the content-hash tag computation."""

    @patch.dict(os.environ, {"CLEARWING_SANDBOX_REGISTRY": "ghcr.io/org/sandbox"})
    def test_deterministic_tag(self):
        from clearwing.sandbox.kube_builder import compute_registry_tag

        tag1 = compute_registry_tag("FROM debian\n", ["asan"], ["git"], ["echo hello"])
        tag2 = compute_registry_tag("FROM debian\n", ["asan"], ["git"], ["echo hello"])
        self.assertEqual(tag1, tag2)
        self.assertTrue(tag1.startswith("ghcr.io/org/sandbox:"))

    @patch.dict(os.environ, {"CLEARWING_SANDBOX_REGISTRY": "ghcr.io/org/sandbox"})
    def test_different_content_different_tag(self):
        from clearwing.sandbox.kube_builder import compute_registry_tag

        tag1 = compute_registry_tag("FROM debian\n", ["asan"], ["git"], [])
        tag2 = compute_registry_tag("FROM ubuntu\n", ["asan"], ["git"], [])
        self.assertNotEqual(tag1, tag2)


if __name__ == "__main__":
    unittest.main()
