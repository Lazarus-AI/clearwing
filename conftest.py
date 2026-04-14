"""Repo-root pytest configuration."""

# Phase 1 will activate this filter to turn every deprecated-shim import into a
# hard test failure, locking the trunk against regression once the 22 shim
# packages are demolished. Leave commented until then — the suite still
# imports through shims today.
#
# import warnings
#
# def pytest_configure(config):
#     warnings.filterwarnings("error", category=DeprecationWarning, module=r"vulnexploit\..*")

# Phase 1 will migrate vulnexploit/tests/ to top-level tests/ with canonical
# imports and delete the in-package tree entirely. Until then, test_memory.py
# cannot even load because the vulnexploit.memory shim re-exports only
# top-level names, not submodule paths like vulnexploit.memory.session_store.
collect_ignore = ["vulnexploit/tests/test_memory.py"]
