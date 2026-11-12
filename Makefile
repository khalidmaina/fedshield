# FedShield common commands. Run from the repository root; the project's .venv is used automatically.
#   make help
.PHONY: help install lint format test smoke-quick smoke testbed-up testbed-down testbed-status compose-check \
        install-bpftrace collect features-report schedules session dataset dataset-report clean

# The project's virtual environment when it exists (activated or not), otherwise python3.
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
# make collect DURATION=7200 for one 2-hour session (0 = until Ctrl+C)
DURATION ?= 0

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
	@echo "make install-bpftrace       install the verified bpftrace v0.20.2 (decision 0007)"
	@echo "make collect DURATION=120   run the eBPF collector (sudo, system Python) into data/features/"
	@echo "make features-report        summarise the latest collector run (hosts, gaps, loss, medians)"
	@echo "make schedules              rewrite testbed/schedules/ (8 sessions, decision 0003)"
	@echo "make session N=1            run collection session N (collector must be running)"
	@echo "make dataset                build data/processed/host_windows.csv from features + labels"
	@echo "make dataset-report         what the dataset holds per split, host and attack (RQ5 check)"

install:
	@$(PY) -c "import sys; sys.exit(sys.prefix == sys.base_prefix)" || \
	  { echo "No virtual environment: run  python3.12 -m venv .venv  first."; exit 1; }
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install torch==2.5.1 --index-url https://download.pytorch.org/whl/cpu
	$(PY) -m pip install -r requirements.txt -r requirements-dev.txt
	$(PY) -m pip install -e . --no-deps

lint:
	$(PY) -m ruff check .

format:
	$(PY) -m ruff check --fix .

test:
	$(PY) -m pytest

smoke-quick:
	@if [ -f tests/smoke_test.py ]; then $(PY) tests/smoke_test.py --quick; \
	else echo "No smoke test yet: it is rebuilt with the FL core in Sprint 5."; fi

smoke:
	@if [ -f tests/smoke_test.py ]; then $(PY) tests/smoke_test.py; \
	else echo "No smoke test yet: it is rebuilt with the FL core in Sprint 5."; fi

testbed-up:
	@# control folders must exist and be yours before Docker would create them as root (decision 0009)
	for r in web db build dev; do for i in 1 2 3; do mkdir -p testbed/control/fs-$$r-$$i; done; done
	cd testbed && docker compose up -d --build

testbed-down:
	cd testbed && docker compose down

testbed-status:
	$(PY) scripts/testbed.py status

install-bpftrace:
	./scripts/install_bpftrace.sh

collect:
	sudo /usr/bin/python3 collector/collector.py --duration $(DURATION)

features-report:
	$(PY) scripts/features_report.py

schedules:
	$(PY) scripts/make_schedule.py

session:
	@test -n "$(N)" || (echo "usage: make session N=<session number 1-8>"; exit 2)
	$(PY) scripts/run_session.py --session $(N)

dataset:
	$(PY) scripts/build_dataset.py

dataset-report:
	$(PY) scripts/dataset_report.py

compose-check:
	cd testbed && docker compose config --quiet && echo "docker-compose.yml is valid"

clean:
	rm -rf .pytest_cache .ruff_cache results/smoke data/processed/smoke_windows.csv
	find . -name __pycache__ -prune -exec rm -rf {} +
