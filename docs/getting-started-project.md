# Getting started with a Daml project

1) Build your project to produce a DAR:
```bash
daml build
```

2) Scan the latest DAR in the project directory:
```bash
daml-sast scan --project . --format sarif --fail-on MEDIUM
```
`--project` will pick the newest `.dar` under `.daml/dist` (and run `daml build` unless `--no-build` is set).

3) Save a baseline (optional):
```bash
daml-sast scan --project . --write-baseline baseline.json
```

4) Use suppressions/baselines in CI:
```bash
daml-sast scan --project . --baseline baseline.json --format sarif --ci
```

Tip: add `.daml-sast-ignore` to hold intentional waivers. Use `--suppressions <path>` if you store it elsewhere.
