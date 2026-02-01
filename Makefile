PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
PIP := $(BIN)/pip
PYTHON := $(BIN)/python

.PHONY: help venv deps dev-deps test lint typecheck build clean

help:
	@echo "Targets:"
	@echo "  venv      - create virtual environment in $(VENV)"
	@echo "  deps      - install runtime dependencies"
	@echo "  dev-deps  - install runtime + dev dependencies"
	@echo "  test      - run unit tests"
	@echo "  lint      - run ruff lint"
	@echo "  typecheck - run mypy"
	@echo "  build     - build wheel"
	@echo "  clean     - remove virtual environment"

venv:
	@test -x $(PYTHON) || $(PY) -m venv $(VENV)

# Runtime deps only
deps: venv
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

# Runtime + dev deps (proto generation tooling, etc.)
# NOTE: uses optional extra defined in pyproject.toml
#       If you don't need dev tools, use `make deps`.
dev-deps: venv
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .


test: deps
	$(PYTHON) -m unittest discover -s tests -p "test_*.py"

lint: dev-deps
	$(PYTHON) -m ruff check .

typecheck: dev-deps
	$(PYTHON) -m mypy daml_sast

build: dev-deps
	$(PYTHON) -m build --wheel

clean:
	rm -rf $(VENV)
