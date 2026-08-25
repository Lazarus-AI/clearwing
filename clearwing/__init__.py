"""Clearwing - Comprehensive Vulnerability Scanner and Exploiter."""

from .core import Config, CoreEngine
from .core.config import ScanConfig

__all__ = ["CoreEngine", "Config", "ScanConfig"]
__version__ = "1.0.0"


def main():
    """Main entry point for Clearwing."""
    from .observability.integration import ObservabilityIntegration
    from .ui.cli import CLI

    # Auto-wire standard OTLP tracing when configured. Phoenix environment
    # variables remain accepted as compatibility aliases.
    observability = ObservabilityIntegration.bootstrap_from_env()
    try:
        cli = CLI()
        cli.run()
    finally:
        if observability is not None:
            observability.disconnect()
