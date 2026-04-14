"""Repo-root pytest configuration."""

import warnings


def pytest_configure(config):
    """Turn any clearwing DeprecationWarning into a hard test failure.

    Phase 1e deleted the 22 legacy shim packages; this filter locks the trunk
    against accidental re-introduction of a deprecated import path.
    """
    warnings.filterwarnings(
        "error",
        category=DeprecationWarning,
        module=r"clearwing\..*",
    )
