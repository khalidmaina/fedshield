# FedShield common commands. Run from the repository root with the venv active.
#   make help
.PHONY: help install lint format test smoke-quick smoke testbed-up testbed-down testbed-status compose-check clean

PY ?= python

help:
	@echo "make install        install PyTorch (CPU), runtime and dev libraries into the active venv"
	@echo "make lint           ruff lint check (what CI runs)"
	@echo "make format         auto-fix import order and simple lint issues"
	@echo "make test           fast unit tests (what CI runs)"
	@echo "make smoke-quick    a few FL modes on synthetic data (what CI runs, ~2 min)"
	@echo "make smoke          every mode on synthetic data (~5-10 min)"
	@echo "make testbed-up     build and start the 12 hosts + c2-server"
	@echo "make testbed-down   stop the testbed"
	@echo "make testbed-status check all 13 containers from outside (scripts/testbed.py status)"
	@echo "make compose-check  validate testbed/docker-compose.yml"

install:
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install torch==2.5.1 --index-url https://download.pytorch.org/whl/cpu
	$(PY) -m pip install -r requirements.txt -r requirements-dev.txt
	$(PY) -m pip install -e . --no-deps

lint:
	ruff check .

format:
	ruff check --fix .

test:
	$(PY) -m pytest

smoke-quick:
	@if [ -f tests/smoke_test.py ]; then $(PY) tests/smoke_test.py --quick; \
	else echo "No smoke test yet: it is rebuilt with the FL core in Sprint 5."; fi

smoke:
	@if [ -f tests/smoke_test.py ]; then $(PY) tests/smoke_test.py; \
	else echo "No smoke test yet: it is rebuilt with the FL core in Sprint 5."; fi

testbed-up:
	mkdir -p testbed/control       # must exist (and be yours) before Docker would create it as root
	cd testbed && docker compose up -d --build

testbed-down:
	cd testbed && docker compose down

testbed-status:
	$(PY) scripts/testbed.py status

compose-check:
	cd testbed && docker compose config --quiet && echo "docker-compose.yml is valid"

clean:
	rm -rf .pytest_cache .ruff_cache results/smoke data/processed/smoke_windows.csv
	find . -name __pycache__ -prune -exec rm -rf {} +
