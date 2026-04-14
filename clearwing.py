#!/usr/bin/env python3
"""
Clearwing - Comprehensive Vulnerability Scanner and Exploiter

A modular, extensible tool designed to identify and exploit vulnerabilities
in target systems.
"""

import sys
from clearwing.ui.cli import CLI


def main():
    """Main entry point for Clearwing."""
    cli = CLI()
    cli.run()


if __name__ == '__main__':
    main()
