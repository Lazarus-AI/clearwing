# Clearwing Tests

This directory contains test cases for Clearwing modules.

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=clearwing

# Run specific test file
pytest tests/test_scanners.py

# Run specific test
pytest tests/test_scanners.py::TestPortScanner::test_syn_scan
```

## Test Structure

- `test_scanners.py`: Tests for port, service, vulnerability, and OS scanners
- `test_reporting.py`: Tests for report generation
- `test_core.py`: Tests for core engine and configuration
- `test_exploiters.py`: Tests for exploitation modules
