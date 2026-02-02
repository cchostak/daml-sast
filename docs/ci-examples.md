# CI examples

## GitHub Actions (Docker image)

```yaml
name: daml-sast
on:
  pull_request:
  push:
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t daml-sast .
      - name: Scan DARs
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -w /workspace \
            daml-sast \
            scan --dar testdata/external/dars/sample-findings.dar --format sarif > sast.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sast.sarif
```

## GitLab CI (Docker image)

```yaml
stages: [scan]

daml_sast:
  stage: scan
  image: docker:25
  services:
    - docker:25-dind
  variables:
    DOCKER_DRIVER: overlay2
  script:
    - docker build -t daml-sast .
    - docker run --rm -v $CI_PROJECT_DIR:/workspace -w /workspace daml-sast scan --dar testdata/external/dars/sample-findings.dar --format sarif > sast.sarif
  artifacts:
    when: always
    paths:
      - sast.sarif
```

Notes:
- Replace the DAR path with your build artifact or `--project <dir>` if building inside the container.
- Add `--fail-on HIGH` (or preferred level) to make the pipeline fail on serious findings.
- Suppressions: mount `.daml-sast-ignore` (default picked up) or pass `--suppressions <path>`.
