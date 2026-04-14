import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    """Configuration for scanning operations."""
    target: str = ""
    ports: list = field(default_factory=lambda: list(range(1, 1025)))
    scan_type: str = "syn"
    threads: int = 100
    timeout: int = 1
    os_detection: bool = True
    service_detection: bool = True
    vulnerability_scan: bool = True
    exploit: bool = False
    output_format: str = "text"
    output_file: Optional[str] = None
    log_file: Optional[str] = None
    verbose: bool = False
    stealth_mode: bool = False
    decoy_count: int = 0
    fragment_packets: bool = False


class Config:
    """Configuration management for Clearwing."""
    
    DEFAULT_CONFIG = {
        'scanning': {
            'default_ports': list(range(1, 1025)) + [3389, 5900, 8080, 8443],
            'common_ports': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080],
            'scan_timeout': 1,
            'max_threads': 100,
            'retry_count': 2
        },
        'exploitation': {
            'auto_exploit': False,
            'metasploit_host': '127.0.0.1',
            'metasploit_port': 55553,
            'metasploit_password': 'msf'
        },
        'reporting': {
            'default_format': 'text',
            'include_recommendations': True,
            'include_mitigations': True
        },
        'database': {
            'path': 'clearwing.db',
            'auto_backup': True
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_file:
            self.load(config_file)
    
    def load(self, config_file: str) -> None:
        """Load configuration from a YAML file."""
        path = Path(config_file)
        if path.exists():
            with open(path, 'r') as f:
                file_config = yaml.safe_load(f)
                self._merge_config(file_config)
    
    def _merge_config(self, new_config: Dict[str, Any]) -> None:
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
        with open(path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
    
    def get(self, *keys, default=None) -> Any:
        """Get a configuration value by nested keys."""
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
            else:
                return default
        return value
    
    def set(self, *keys, value: Any) -> None:
        """Set a configuration value by nested keys."""
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
