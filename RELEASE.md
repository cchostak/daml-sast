# Release Checklist

1) Update version:
   - `pyproject.toml` version
   - `daml_sast/__init__.py` (`__version__`)

2) Update `CHANGELOG.md`:
   - Summarize changes and notable fixes.

3) Run local checks:
   - `make dev-deps`
   - `make lint`
   - `make typecheck`
   - `make test`
   - `make build`

4) Tag and push:
   - `git tag -a vX.Y.Z -m "vX.Y.Z"`
   - `git push --tags`

5) Publish (GitHub Actions):
   - Create a GitHub release for the tag.
   - The `publish` workflow runs lint/typecheck/tests before building and uploading to PyPI.

Optional signing:
   - Add `GPG_PRIVATE_KEY` and (optionally) `GPG_PASSPHRASE` secrets.
   - The publish workflow will generate `.asc` signatures and upload them alongside artifacts.
