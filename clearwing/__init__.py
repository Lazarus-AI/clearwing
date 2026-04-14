"""Clearwing - Comprehensive Vulnerability Scanner and Exploiter."""

from .core import Config, CoreEngine
from .core.config import ScanConfig

__all__ = ["CoreEngine", "Config", "ScanConfig"]
__version__ = "1.0.0"


def main():
    """Main entry point for Clearwing."""
    from .ui.cli import CLI

    cli = CLI()
    cli.run()
