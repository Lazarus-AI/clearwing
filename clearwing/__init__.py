"""Clearwing - Comprehensive Vulnerability Scanner and Exploiter."""

from .core import Config, CoreEngine
from .core.config import ScanConfig

__all__ = ["CoreEngine", "Config", "ScanConfig"]
__version__ = "1.0.0"


def main():
    """Main entry point for Clearwing."""
    from .observability.integration import ObservabilityIntegration
    from .ui.cli import CLI

    # Auto-wire Phoenix / OTLP tracing when PHOENIX_ENDPOINT is set. No-op
    # otherwise, so plain `clearwing …` invocations without the env vars pay
    # zero cost.
    ObservabilityIntegration.bootstrap_from_env()

    cli = CLI()
    cli.run()
