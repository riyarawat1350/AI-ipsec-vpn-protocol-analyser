#!/usr/bin/env bash
set -e

echo "=== Running Python Linting (ruff) ==="
ruff check analyzer backend tests

echo "=== Running Static Type Analysis (mypy) ==="
mypy analyzer

echo "=== Running Python Test Suite (pytest) ==="
pytest -v --cov=analyzer --cov-report=term-missing

echo "=== Running Frontend Build Check ==="
cd frontend
npm run build
cd ..

echo "=== CI Checks Passed Successfully ==="
