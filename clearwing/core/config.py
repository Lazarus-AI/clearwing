import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


def clearwing_home() -> Path:
    """Return the Clearwing home directory.

    Resolution order:
      1. ``CLEARWING_HOME`` environment variable
      2. ``~/.clearwing``
    """
    raw = os.environ.get("CLEARWING_HOME")
    if raw:
        return Path(raw).expanduser().resolve()
    return Path.home() / ".clearwing"


def _is_dev_checkout() -> bool:
    """True when running from a git checkout (developer install)."""
    return (Path(__file__).resolve().parent.parent.parent / ".git").is_dir()


def default_results_dir(subdir: str) -> str:
    """Return the default output directory for a pipeline.

    In a dev checkout results land in ``./results/<subdir>`` (relative to
    cwd).  For a PyPI install they go to ``~/.clearwing/results/<subdir>``
    so nothing is written into an arbitrary working directory.
    """
    if _is_dev_checkout():
        return f"./results/{subdir}"
    return str(clearwing_home() / "results" / subdir)


@dataclass
class SourceHuntLimits:
    """Centralized limits for the sourcehunt pipeline.

    Every module reads its limits from this single dataclass.  Defaults
    match the previously-hardcoded values for backward compatibility.
    """

    max_file_size: int = 1_000_000
    max_matches_per_pattern: int = 50
    max_entry_points_per_file: int = 20
    max_entries_per_file: int = 10
    max_seed_context_chars: int = 2000
    max_dedup_candidates: int = 3
    max_disclosure_batch_size: int = 5
    semgrep_timeout_seconds: int = 300

    @classmethod
    def from_env(cls) -> "SourceHuntLimits":
        """Build limits with env-var overrides."""
        kwargs: dict[str, int] = {}
        if val := os.environ.get("CLEARWING_MAX_FILE_SIZE"):
            kwargs["max_file_size"] = int(val)
        if val := os.environ.get("CLEARWING_SEMGREP_TIMEOUT"):
            kwargs["semgrep_timeout_seconds"] = int(val)
        if val := os.environ.get("CLEARWING_MAX_MATCHES_PER_PATTERN"):
            kwargs["max_matches_per_pattern"] = int(val)
        if val := os.environ.get("CLEARWING_MAX_ENTRY_POINTS_PER_FILE"):
            kwargs["max_entry_points_per_file"] = int(val)
        return cls(**kwargs)


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
            "metasploit_password": os.environ.get("CLEARWING_MSF_PASSWORD", "msf"),
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
    DEFAULT_CONFIG_PATH = clearwing_home() / "config.yaml"

    #: The user's personal config in ~/.clearwing/, which always holds
    #: provider credentials regardless of CLEARWING_HOME overrides.
    _USER_CONFIG_PATH = Path.home() / ".clearwing" / "config.yaml"

    def __init__(self, config_file: str | None = None):
        self.config = self.DEFAULT_CONFIG.copy()
        # Load from CLEARWING_HOME (or ~/.clearwing) first.
        if self.DEFAULT_CONFIG_PATH.exists():
            self.load(str(self.DEFAULT_CONFIG_PATH))
        # When CLEARWING_HOME points elsewhere (e.g. a blind-test
        # sandbox), still load the user's personal config for provider
        # credentials — scan isolation shouldn't lock out LLM access.
        if (
            self.DEFAULT_CONFIG_PATH != self._USER_CONFIG_PATH
            and self._USER_CONFIG_PATH.exists()
        ):
            self.load(str(self._USER_CONFIG_PATH))
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
