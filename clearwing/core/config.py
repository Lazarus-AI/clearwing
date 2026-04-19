from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


@dataclass
class ScanConfig:
    """Configuration for scanning operations."""

    target: str = ""
    ports: list = field(default_factory=lambda: list(range(1, 1025)))
    # Default to "connect" (TCP connect / nmap -sT): works without root on
    # every OS. "syn" (raw-socket SYN scan via scapy) needs root + a route
    # to a usable IP source; without it scapy silently drops every probe
    # and the report looks empty. Users can opt back into SYN explicitly.
    scan_type: str = "connect"
    threads: int = 100
    timeout: int = 1
    os_detection: bool = True
    service_detection: bool = True
    vulnerability_scan: bool = True
    exploit: bool = False
    output_format: str = "text"
    output_file: str | None = None
    log_file: str | None = None
    verbose: bool = False
    stealth_mode: bool = False
    decoy_count: int = 0
    fragment_packets: bool = False


class Config:
    """Configuration management for Clearwing."""

    DEFAULT_CONFIG = {
        "scanning": {
            "default_ports": list(range(1, 1025)) + [3389, 5900, 8080, 8443],
            "common_ports": [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                143,
                443,
                445,
                993,
                995,
                3306,
                3389,
                5900,
                8080,
            ],
            "scan_timeout": 1,
            "max_threads": 100,
            "retry_count": 2,
        },
        "exploitation": {
            "auto_exploit": False,
            "metasploit_host": "127.0.0.1",
            "metasploit_port": 55553,
            "metasploit_password": "msf",
        },
        "reporting": {
            "default_format": "text",
            "include_recommendations": True,
            "include_mitigations": True,
        },
        "database": {"path": "clearwing.db", "auto_backup": True},
    }

    #: Default path searched when no explicit config_file is passed.
    #: Users can put provider / scan / exploitation settings here and
    #: they persist across sessions.
    DEFAULT_CONFIG_PATH = Path.home() / ".clearwing" / "config.yaml"

    def __init__(self, config_file: str | None = None):
        self.config = self.DEFAULT_CONFIG.copy()
        # Always try the default path first — users expect
        # `~/.clearwing/config.yaml` to be auto-discovered.
        if self.DEFAULT_CONFIG_PATH.exists():
            self.load(str(self.DEFAULT_CONFIG_PATH))
        if config_file:
            self.load(config_file)

    # ---- Provider section accessors --------------------------------------

    def get_provider_section(self) -> dict[str, Any]:
        """Return the `provider:` section of the config, or {}.

        Shape (all fields optional):
            provider:
              base_url: https://openrouter.ai/api/v1
              api_key: ${OPENROUTER_API_KEY}
              model: anthropic/claude-opus-4
        """
        section = self.config.get("provider")
        return dict(section) if isinstance(section, dict) else {}

    def get_providers_config(self) -> dict[str, Any]:
        """Return the full multi-provider routing config.

        Shape (all fields optional):
            providers:
              openrouter:
                base_url: https://openrouter.ai/api/v1
                api_key: ${OPENROUTER_API_KEY}
              local_llama:
                base_url: http://localhost:11434/v1
                api_key: ollama
            routes:
              default: openrouter
              hunter: openrouter
              verifier: local_llama
            task_models:
              hunter: anthropic/claude-opus-4
              verifier: qwen2.5-coder:32b
        """
        out: dict[str, Any] = {}
        if "provider" in self.config:
            out["provider"] = self.config["provider"]
        if "providers" in self.config:
            out["providers"] = self.config["providers"]
        if "routes" in self.config:
            out["routes"] = self.config["routes"]
        if "task_models" in self.config:
            out["task_models"] = self.config["task_models"]
        return out

    def load(self, config_file: str) -> None:
        """Load configuration from a YAML file."""
        path = Path(config_file)
        if path.exists():
            with open(path) as f:
                file_config = yaml.safe_load(f)
                self._merge_config(file_config)

    def _merge_config(self, new_config: dict[str, Any]) -> None:
        """Merge new configuration with existing configuration."""
        for key, value in new_config.items():
            if isinstance(value, dict) and key in self.config:
                self.config[key].update(value)
            else:
                self.config[key] = value

    def save(self, config_file: str) -> None:
        """Save current configuration to a YAML file."""
        path = Path(config_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self.config, f, default_flow_style=False)

    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a configuration value by nested keys."""
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
        return value

    def set(self, *keys: str, value: Any) -> None:
        """Set a configuration value by nested keys."""
        config: dict[str, Any] = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
