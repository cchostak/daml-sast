# Policy examples

Recommended settings per environment.

## Local dev
- Command: `daml-sast scan --dar <path> --format json --fail-on HIGH`
- Suppressions: allow `.daml-sast-ignore` locally; avoid baselines unless needed.

## CI (PRs)
- Command: `daml-sast scan --dar <path> --format sarif --fail-on MEDIUM --ci`
- Publish SARIF to code host (see `docs/ci-examples.md`).
- Use `.daml-sast-ignore` for intentional patterns; keep small.

## CI (main / release)
- Command: `daml-sast scan --dar <path> --format sarif --fail-on HIGH --ci --baseline baseline.json`
- Regenerate baseline intentionally when rules or code change.

## Suggested flags
- `--fail-on MEDIUM|HIGH` to enforce policy.
- `--suppressions .daml-sast-ignore` (default) to allow targeted waivers.
- `--baseline`/`--write-baseline` for stable fingerprints in long-lived branches.
