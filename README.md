# daml-sast

Bandit-like static analyzer for Daml-LF (DAR/DALF) artifacts.

## Quick start

```bash
make deps
make test
```

Lint/typecheck/build:

```bash
make lint
make typecheck
make build
```

Scan a DAR:

```bash
.venv/bin/daml-sast scan --dar path/to/project.dar
```

## Config file (TOML)

Example `daml-sast.toml`:

```toml
[scanner]
format = "sarif"
severity = "MEDIUM"
fail_on = "HIGH"
ci = true

[rules]
allow = ["DAML-AUTH-001", "DAML-LIFE-001"]
deny = ["DAML-PRIV-001"]

[baseline]
path = "baseline.json"
# write can be a path or boolean; if string, treated as path
write = "baseline.json"
```

Run with config:

```bash
.venv/bin/daml-sast scan --dar path/to/project.dar --config daml-sast.toml
```

## Baselines

Baselines are JSON files with a list of fingerprints:

```json
{
  "fingerprints": ["<sha256>", "<sha256>"]
}
```

Use:
- `--baseline <path>` to suppress findings present in the baseline.
- `--write-baseline <path>` to write current findings to a baseline.

## Exit codes

- `0` success (no findings at/above `--fail-on`, or `--fail-on` unset)
- `1` findings at/above `--fail-on`
- `2` usage/config error
- `3` scan error (decode/lower failures)

## CI

Pass `--ci` to add SARIF run metadata (invocation timestamps, automation details) and default `--fail-on` to `MEDIUM` if not set.

## Packaging

- Runtime pins: `requirements.txt`
- Dev pins (lint/typecheck/build): `requirements-dev.txt`
- Build wheel: `make build`

## Docs

- `docs/README.md` — Index
- `docs/08-rule-catalog.md` — Rule catalog
- `docs/09-interpret-findings.md` — How to interpret findings
