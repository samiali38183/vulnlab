PYTHON ?= python

.PHONY: setup test lint demo record

setup:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install -e ".[dev]" || .venv/Scripts/python -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q
	$(PYTHON) tools/sinkline_check.py
	sigma check labs/*/detection/*.yml

lint:
	ruff check .
	ruff format --check .

demo:
	bash tools/demo.sh

# Refresh the recorded detection samples from a real run of the tests.
record:
	VULNLAB_RECORD=1 $(PYTHON) -m pytest -q labs
