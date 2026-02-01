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

5) Publish wheel:
   - `python -m build --wheel`
   - `twine upload dist/*.whl`
