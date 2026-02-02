# How to interpret findings

## Severity vs confidence
- Severity answers: "How bad could this be if it's real?"
- Confidence answers: "How likely is it to be real?"
- Interpret combos:
  - HIGH severity + HIGH confidence: fix quickly or justify.
  - HIGH severity + LOW confidence: review design; likely intentional but confirm.
  - LOW severity + HIGH confidence: can defer, but document rationale.

## Finding fields
- `id`: Rule ID (e.g., `DAML-AUTH-001`).
- `message`: Short description of the issue.
- `location`: Module + definition; span may be missing in LF.
- `evidence`: Pointers to relevant expressions.
- `metadata`: Extra context (template, choice, etc.).
- `fingerprint`: Stable hash used for suppression/baselines.

## Triage workflow
1. Read the rule description in the catalog.
2. Check `metadata` for template/choice context.
3. Inspect the Daml source to confirm intent.
4. Decide: fix, redesign, or suppress with justification.

## Suppressions and baselines
- Suppression file (default `.daml-sast-ignore`): each line `RULE [module] [definition] [fingerprint]`; `*` globs allowed.
- Baseline JSON:
  - Generate: `daml-sast scan --write-baseline baseline.json`
  - Apply: `daml-sast scan --baseline baseline.json`
- Review suppressions/baselines periodically so they stay intentional.

## Known limitations
- Analyzer works on compiled Daml-LF; source spans may be missing.
- Party inference is conservative; complex logic can show as "unknown".
- Rules are heuristic; use confidence to gauge review depth.

## When to escalate
- Nonconsuming choices that mint/duplicate assets.
- Broadening controllers/signatories or observers.
- Time-dependent auth/key logic.
- Any HIGH severity finding that isn't clearly intentional.
