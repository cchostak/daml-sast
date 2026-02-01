PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
PIP := $(BIN)/pip
PYTHON := $(BIN)/python

.PHONY: help venv deps dev-deps test lint typecheck build dar-tests clean

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

DAR_DIR ?= testdata/external/dars
DAR_GLOB ?= $(DAR_DIR)/*.dar
DAR_IGNORE_ERRORS ?= 0

dar-tests: deps
	@test -d $(DAR_DIR) || (echo "missing $(DAR_DIR); download DARs first" && exit 1)
	@set -e; \
	errors=0; \
	found=0; \
	for dar in $(DAR_GLOB); do \
		if [ ! -e "$$dar" ]; then \
			continue; \
		fi; \
		found=1; \
		echo "scanning $$dar"; \
		if ! $(PYTHON) -m daml_sast.cli scan --dar "$$dar" --format json > /dev/null; then \
			echo "scan failed: $$dar"; \
			errors=$$((errors+1)); \
		fi; \
	done; \
	if [ "$$found" -eq 0 ]; then \
		echo "no .dar files found for $(DAR_GLOB)"; \
		exit 1; \
	fi; \
	if [ "$$errors" -gt 0 ]; then \
		echo "$$errors DAR(s) failed"; \
		if [ "$(DAR_IGNORE_ERRORS)" != "1" ]; then \
			exit 1; \
		fi; \
	fi

clean:
	rm -rf $(VENV)
