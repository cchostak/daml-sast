VENV ?= .venv

# Pick correct venv binary locations per-platform
ifeq ($(OS),Windows_NT)
DEFAULT_PY := python
BIN := $(VENV)\\Scripts
PYTHON := $(BIN)\\python.exe
else
DEFAULT_PY := python3
BIN := $(VENV)/bin
PYTHON := $(BIN)/python
endif

PY ?= $(DEFAULT_PY)
PIP := $(PYTHON) -m pip

.PHONY: help venv deps dev-deps test lint typecheck build dar-tests fetch-dars clean

help:
	@echo "Targets:"
	@echo "  venv      - create virtual environment in $(VENV)"
	@echo "  deps      - install runtime dependencies"
	@echo "  dev-deps  - install runtime + dev dependencies"
	@echo "  test      - run unit tests"
	@echo "  lint      - run ruff lint"
	@echo "  typecheck - run mypy"
	@echo "  build     - build wheel"
	@echo "  dar-tests - scan DARs under testdata/external/dars (use DAR_GLOB=... to filter)"
	@echo "  fetch-dars- download DAR fixtures into $(DAR_DIR) (edit $(DAR_MANIFEST) or pass DAR_SOURCES=...)"
	@echo "  clean     - remove virtual environment"

venv:
ifeq ($(OS),Windows_NT)
	@if not exist "$(PYTHON)" ( $(PY) -m venv $(VENV) )
	@$(PYTHON) -m ensurepip --upgrade >NUL
else
	@test -x "$(PYTHON)" || $(PY) -m venv $(VENV)
	@$(PYTHON) -m ensurepip --upgrade >/dev/null
endif

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

DAR_DIR ?= testdata/external/dars
DAR_GLOB ?= $(DAR_DIR)/*.dar
DAR_IGNORE_ERRORS ?= 0
DAR_MANIFEST ?= testdata/external/dars.manifest
DAR_SOURCES ?=

fetch-dars: venv
	@$(PYTHON) scripts/gen_sample_dars.py --out "$(DAR_DIR)"
	@$(PYTHON) scripts/fetch_dars.py --dir "$(DAR_DIR)" --manifest "$(DAR_MANIFEST)" --urls "$(DAR_SOURCES)"

dar-tests: deps
	@$(PYTHON) scripts/dar_tests.py "$(DAR_GLOB)" "$(DAR_DIR)" "$(DAR_IGNORE_ERRORS)"

clean:
	$(PY) -c "import shutil, pathlib; shutil.rmtree(r'$(VENV)', ignore_errors=True)"
