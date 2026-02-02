# daml-sast

![ci](https://github.com/cchostak/daml-sast/actions/workflows/ci.yml/badge.svg)

Bandit-like static analyzer for Daml-LF (DAR/DALF) artifacts.

## What this can do

- Scan DAR/DALF archives for a focused set of security and stability rules.
- Emit JSON or SARIF for CI integration and code review.
- Suppress known findings via versioned baselines or per-finding suppressions.

## What this can't do

- Compile Daml source or analyze code outside compiled Daml-LF.
- Prove correctness or absence of issues (heuristic, best-effort analysis).
- Fully understand complex party logic beyond simple inference patterns.

## Supported Daml-LF versions

- LF1: 1.6, 1.7, 1.8, 1.11, 1.14, 1.15, 1.17
- LF2: 2.1

## Known limitations

- Analyzer operates on Daml-LF only; source spans may be missing or imprecise.
- Party inference is conservative; complex logic can yield unknowns.
- Rules are heuristic and may produce false positives or miss nuanced cases.
- Large or malformed DARs are rejected once input hardening limits are exceeded.

## Test fixtures (DARs)

`make dar-tests` expects sample DAR archives under `testdata/external/dars`.

```
make fetch-dars
```

The fetcher reads URLs from `testdata/external/dars.manifest` (one per line, optionally with filename and sha256). You can also bypass the manifest by passing `DAR_SOURCES="https://example.com/foo.dar ..."`.

## Semgrep parity (Solidity-inspired)

We track only the rules that make sense for Daml/LF (no EVM opcodes/gas). Summary:

- DAML-AUTH-001 - controllers not subset of signatories/maintainers
- DAML-AUTH-002 - controllers from uncontrolled data
- DAML-AUTH-003 - template with empty signatories
- DAML-AUTH-004 - nonconsuming forwarding via exercise
- DAML-KEY-001 - key maintainers not subset of signatories
- DAML-PRIV-001 - over-broad observers
- DAML-LIFE-001 - nonconsuming creates same template
- DAML-LIFE-002 - nonconsuming creates any contract
- DAML-DET-001 - time in auth/key logic

See `docs/semgrep-parity.md` for the mapping table and N/A items.

## Suppressions

- Suppression file (default: `.daml-sast-ignore`): each line `RULE [module] [definition] [fingerprint]`, `*` globs allowed.
- Baseline JSON: `--baseline` to suppress existing fingerprints; `--write-baseline` to regenerate.

## Telemetry and privacy

No telemetry is collected. See `docs/10-telemetry-privacy.md` for details.

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

Baselines are JSON files with tool + ruleset versions and a list of fingerprints:

```json
{
  "tool_version": "0.0.1",
  "rules_version": "1",
  "fingerprints": ["<sha256>", "<sha256>"]
}
```

Use:
- `--baseline <path>` to suppress findings present in the baseline.
- `--write-baseline <path>` to write current findings to a baseline.
Mismatched versions are rejected to avoid suppressing stale findings; regenerate if needed.

## Exit codes

- `0` success (no findings at/above `--fail-on`, or `--fail-on` unset)
- `1` findings at/above `--fail-on`
- `2` usage/config error
- `3` scan error (decode/lower failures)

## CI

Pass `--ci` to add SARIF run metadata (invocation timestamps, automation details) and default `--fail-on` to `MEDIUM` if not set.

## Docs

- `docs/README.md` - Index
- `docs/08-rule-catalog.md` - Rule catalog
- `docs/09-interpret-findings.md` - How to interpret findings
- `docs/10-telemetry-privacy.md` - Telemetry and privacy statement
- `docs/semgrep-parity.md` - Solidity-inspired rule parity
- `docs/terms.md` - Glossary (plain language)
- `docs/ci-examples.md` - Docker + CI snippets (GitHub Actions, GitLab CI)

## Contributing and security

- `CONTRIBUTING.md` - Contribution guide
- `SECURITY.md` - Security policy

## License

Apache-2.0. See `LICENSE`.
