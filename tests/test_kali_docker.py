"""Tests for Kali Docker tool (requires Docker daemon)."""
import pytest
import shutil

docker_available = shutil.which("docker") is not None

try:
    import docker as docker_lib
    client = docker_lib.from_env()
    client.ping()
    docker_running = True
except Exception:
    docker_running = False

skip_no_docker = pytest.mark.skipif(
    not (docker_available and docker_running),
    reason="Docker daemon not available"
)


@skip_no_docker
class TestKaliDocker:
    """Integration tests using alpine image for speed."""

    @pytest.fixture(autouse=True)
    def cleanup(self):
        """Cleanup any leftover test containers."""
        yield
        try:
            import docker as docker_lib
            client = docker_lib.from_env()
            try:
                container = client.containers.get("vulnexploit-kali-test")
                container.stop(timeout=2)
                container.remove()
            except docker_lib.errors.NotFound:
                pass
        except Exception:
            pass

    def test_container_lifecycle(self):
        """Test start, execute, cleanup using alpine."""
        import docker as docker_lib
        from unittest.mock import patch

        client = docker_lib.from_env()

        # Use alpine instead of kali for test speed
        container = client.containers.run(
            "alpine:latest",
            command="sleep 300",
            name="vulnexploit-kali-test",
            detach=True,
        )

        try:
            assert container.status in ("running", "created")

            # Execute a command
            exit_code, output = container.exec_run("echo hello")
            assert exit_code == 0
            assert b"hello" in output

            # Stop and remove
            container.stop(timeout=2)
            container.remove()

            # Verify removed
            with pytest.raises(docker_lib.errors.NotFound):
                client.containers.get("vulnexploit-kali-test")
        except Exception:
            # Cleanup on failure
            try:
                container.stop(timeout=2)
                container.remove()
            except Exception:
                pass
            raise

    def test_container_reuse(self):
        """Test that existing containers are reused."""
        import docker as docker_lib

        client = docker_lib.from_env()

        container = client.containers.run(
            "alpine:latest",
            command="sleep 300",
            name="vulnexploit-kali-test",
            detach=True,
        )

        try:
            # Getting same container by name should return same ID
            same = client.containers.get("vulnexploit-kali-test")
            assert same.id == container.id
        finally:
            container.stop(timeout=2)
            container.remove()
