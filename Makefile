# Clearwing developer commands. Mirror the CI gate so `make lint type test`
# gives you the same pass/fail signal as a PR.

.PHONY: help install-dev lint format fmt type test test-strict build clean gate all

PY       := venv/bin/python
PYTEST   := $(PY) -m pytest
RUFF     := $(PY) -m ruff
MYPY     := $(PY) -m mypy

MYPY_SCOPE := clearwing/findings clearwing/sourcehunt clearwing/capabilities.py

help:
	@echo "Clearwing developer commands:"
	@echo "  install-dev  pip install -e '.[dev]' (requires venv)"
	@echo "  lint         ruff check + ruff format --check"
	@echo "  format       ruff format (writes changes)"
	@echo "  type         mypy on the scoped gate modules"
	@echo "  test         pytest -q"
	@echo "  test-strict  pytest -q --strict-markers --strict-config (CI mode)"
	@echo "  build        python -m build + twine check"
	@echo "  clean        remove dist/, build/, *.egg-info/, __pycache__/, .pytest_cache/"
	@echo "  gate         lint + type + test-strict + build (full CI gate, local)"
	@echo "  all          alias for gate"

install-dev:
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e '.[dev]'
	$(PY) -m pip install build twine ruff

lint:
	$(RUFF) check clearwing/ tests/
	$(RUFF) format --check clearwing/ tests/

format fmt:
	$(RUFF) format clearwing/ tests/
	$(RUFF) check --fix clearwing/ tests/

type:
	$(MYPY) --follow-imports=silent $(MYPY_SCOPE)

test:
	$(PYTEST) -q

test-strict:
	$(PYTEST) -q --strict-markers --strict-config

build: clean
	$(PY) -m build
	$(PY) -m twine check dist/*

clean:
	rm -rf dist/ build/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true

gate: lint type test-strict build

all: gate
