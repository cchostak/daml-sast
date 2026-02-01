# TODO (Future Enhancements)

- Add a Daml-LF version compatibility matrix and decoding tests.
- Add a rule catalog with documentation and examples for each rule ID.
- Implement optional lightweight dataflow for party-set inference.
- Add taint-like tracking for divulgence sources and sinks.
- Improve type resolution for record field tracking in expressions.
- Add baseline suppression support (e.g., by rule id + location hash).
- Emit SARIF natively (not just JSON mapping) with full `run` metadata.
- Add caching for parsed DAR/DALF to speed CI.
- Expand determinism checks (time, ledger IDs, non-stable IDs).
- Add rule packs for common Daml patterns (asset, settlement, approval).
- Add tests with curated DAR fixtures and expected findings.
