.PHONY: demo setup test check

demo:
	python3 -m flight_recorder demo

setup:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements-dev.txt
	npm ci --ignore-scripts --no-audit --no-fund

test:
	.venv/bin/python -m pytest -q

check:
	.venv/bin/ruff check flight_recorder tests
	.venv/bin/ruff format --check flight_recorder tests
	$(MAKE) test
