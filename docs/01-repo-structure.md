# Repository Structure (MVP)

Assumptions:
- Analysis runs on Daml-LF extracted from .dar/.dalf; no source AST.
- Implementation language is not fixed; layout is language-agnostic.

Folders and responsibilities:
- `cmd/` — CLI entrypoints (binary/main).
- `internal/lf/` — Daml-LF loading and decoding (DAR/DALF parsing).
- `internal/ir/` — Simplified analysis IR built from Daml-LF.
- `internal/walker/` — Traversal of IR (templates, choices, keys, expressions).
- `internal/rules/` — Rule implementations (Bandit-style checks).
- `internal/engine/` — Rule runner, scheduling, and result aggregation.
- `internal/report/` — JSON + SARIF-ready emitters.
- `internal/config/` — CLI/config parsing, rule enable/disable, thresholds.
- `internal/util/` — Common helpers (IDs, spans, hashing, logging).
- `docs/` — Design docs and rule catalog.
- `testdata/` — Sample DAR/DALF fixtures for tests.

Key files (suggested):
- `docs/02-core-ir.md` — Simplified analysis IR definitions.
- `docs/03-rule-interface.md` — Rule interface and metadata.
- `docs/04-cli-scaffold.md` — CLI entrypoint and flags.
- `docs/05-example-rules.md` — Concrete rules with rationale.
- `docs/06-finding-format.md` — Finding JSON + SARIF mapping.
- `docs/07-todo.md` — Future enhancements.

Non-goals (MVP):
- No ledger integration.
- No source-level mapping beyond Daml-LF locations if present.
- No heavyweight program analysis (dataflow/CFG) unless trivial.
