# How to Interpret Findings

This guide explains how to triage findings from `daml-sast` and what the fields mean.

## Severity vs Confidence

- Severity answers: “How bad could this be if it’s real?”
- Confidence answers: “How likely is it to be real?”

Typical interpretations:
- HIGH severity + HIGH confidence: fix quickly or document why it’s safe.
- HIGH severity + LOW confidence: review design; likely intentional but confirm.
- LOW severity + HIGH confidence: safe to defer but document rationale.

## Finding Fields

- `id`: Rule ID (e.g., `DAML-AUTH-001`).
- `message`: Short actionable description.
- `location`: Best-effort location (module + definition + span). Spans may be missing if LF lacks source mapping.
- `evidence`: Pointers to relevant expressions or LF nodes.
- `metadata`: Extra context (template name, choice name, etc.).
- `fingerprint`: Stable hash used for baselines and suppression.

## Recommended Triage Workflow

1) Read the rule description in the rule catalog.
2) Check the `metadata` for template/choice context.
3) Confirm the authorization/observer/key logic in Daml source.
4) Decide whether the pattern is intended or a bug.
5) If intended, add a baseline or suppress (with justification).

## Baselines

Use baselines to suppress known/accepted findings in CI.
- Generate: `daml-sast scan --write-baseline baseline.json`.
- Apply: `daml-sast scan --baseline baseline.json`.

Baselines should be reviewed periodically to ensure they still match intended logic.

## Known Limitations

- Analyzer works on Daml-LF only; no full source AST.
- Party inference is conservative and may return “unknown” for complex logic.
- Some rules are heuristic; use confidence to guide triage.

## When to Escalate

Escalate findings that:
- Involve nonconsuming choices that mint assets.
- Introduce new observers or broaden disclosure boundaries.
- Change controller/signatory relationships.
- Depend on ledger time or other unstable inputs in auth/key logic.
