"""Repo-root pytest configuration."""

# Phase 1f will activate the DeprecationWarning-as-error filter once every
# known shim call site has been rewritten. The filter locks the trunk against
# regression so any accidental re-introduction of a deprecated import path
# fails CI loudly.
#
# import warnings
#
# def pytest_configure(config):
#     warnings.filterwarnings("error", category=DeprecationWarning, module=r"vulnexploit\..*")
