# Glossary (plain language)

- **DAR / DALF**: The compiled Daml application package. This is what the scanner analyzes.
- **Template**: A Daml contract type (like a class). Holds data and defines who may act on it.
- **Signatories**: Parties that must authorize creating and exercising choices on the contract.
- **Observers**: Parties who can see the contract but don’t control it.
- **Controllers**: Parties allowed to exercise a specific choice.
- **Choice**: An operation defined on a template (e.g., “Transfer”, “Redeem”).
- **Consuming choice**: Archives (spends) the contract when exercised.
- **Nonconsuming choice**: Leaves the contract active after exercise.
- **Key maintainers**: Parties responsible for a contract key; must align with signatories.
- **Party literal**: A hardcoded party name in LF (e.g., "Alice").
- **Fingerprint**: Hash derived from a finding to track/suppress it across runs.
- **Suppression file** (`.daml-sast-ignore`): Optional list of findings to skip; format is `RULE [module] [definition] [fingerprint]` with `*` globs allowed.
- **Baseline**: JSON of fingerprints from a known-good run; used to hide unchanged findings.
- **SARIF**: Standard JSON schema for static-analysis results, consumable by CI/code hosts.
- **CI mode**: `--ci` adds timestamps/metadata and defaults `--fail-on` to MEDIUM if unset.
