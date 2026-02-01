# Contributing

Thanks for contributing to daml-sast. This project is intentionally small and explicit about behavior, so please keep changes focused and well-tested.

## Getting started

```bash
make deps
make test
```

Optional checks:

```bash
make lint
make typecheck
make build
```

## Pull request checklist

- Add or update tests for behavior changes.
- Update docs when user-facing behavior changes.
- If you change rule behavior or add/remove rules, update:
  - `docs/08-rule-catalog.md`
  - `daml_sast/rules/version.py` (bump `RULESET_VERSION`)

## Coding notes

- Prefer small, explicit helpers over large abstractions.
- Keep analysis deterministic and avoid nondeterministic sources.
- Be careful with input parsing; DARs may be huge or malformed.

## Reporting issues

If you are reporting a security issue, please follow `SECURITY.md`.
