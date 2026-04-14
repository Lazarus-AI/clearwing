import pytest

from clearwing.core import Config, CoreEngine, ScanConfig
from clearwing.core.engine import ScanState


class TestConfig:
    """Tests for Config module."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        assert config.get("scanning", "max_threads") == 100
        assert not config.get("exploitation", "auto_exploit")

    def test_load_config(self, tmp_path):
        """Test loading configuration from file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
scanning:
  max_threads: 50
exploitation:
  metasploit_host: 192.168.1.100
""")
        config = Config(str(config_file))
        assert config.get("scanning", "max_threads") == 50
        assert config.get("exploitation", "metasploit_host") == "192.168.1.100"

    def test_set_config(self):
        """Test setting configuration values."""
        config = Config()
        config.set("scanning", "timeout", value=5)
        assert config.get("scanning", "timeout") == 5

    def test_save_config(self, tmp_path):
        """Test saving configuration to file."""
        config_file = tmp_path / "config.yaml"
        config = Config()
        config.set("scanning", "max_threads", value=200)
        config.save(str(config_file))
        assert config_file.exists()


class TestCoreEngine:
    """Tests for CoreEngine module."""

    @pytest.fixture
    def engine(self):
        return CoreEngine()

    def test_register_callback(self, engine):
        """Test callback registration."""

        def callback(result):
            pass

        engine.register_callback("on_scan_complete", callback)
        assert len(engine.callbacks["on_scan_complete"]) == 1

    @pytest.mark.asyncio
    async def test_scan_workflow(self, engine):
        """Test complete scan workflow."""
        result = await engine.scan("127.0.0.1")
        assert result.target == "127.0.0.1"
        assert result.state in [ScanState.COMPLETED, ScanState.ERROR]

    def test_get_report(self, engine):
        """Test report generation from engine."""
        report = engine.get_report("text")
        assert isinstance(report, str)


class TestScanConfig:
    """Tests for ScanConfig dataclass."""

    def test_default_values(self):
        """Test default ScanConfig values."""
        config = ScanConfig()
        assert config.target == ""
        assert config.threads == 100
        assert config.timeout == 1
        assert not config.exploit

    def test_custom_values(self):
        """Test custom ScanConfig values."""
        config = ScanConfig(target="192.168.1.1", ports=[22, 80, 443], threads=50, exploit=True)
        assert config.target == "192.168.1.1"
        assert config.ports == [22, 80, 443]
        assert config.threads == 50
        assert config.exploit
