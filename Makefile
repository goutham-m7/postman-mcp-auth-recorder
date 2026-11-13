.PHONY: demo setup test

demo:
	python3 -m flight_recorder demo

setup:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements-dev.txt

test:
	.venv/bin/python -m pytest -q
