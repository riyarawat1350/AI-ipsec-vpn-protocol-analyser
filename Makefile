.PHONY: test lint run fixtures clean verify

test:
	python -m pytest tests/

verify:
	python -m pytest tests/verification/ -v -s

lint:
	ruff check analyzer backend tests
	mypy analyzer

run:
	uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000

fixtures:
	python tests/fixtures/generate_fixtures.py

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
