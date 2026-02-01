# Telemetry and Privacy

## Telemetry

`daml-sast` does not collect or transmit telemetry. The scanner operates locally on the provided DAR/DALF files and produces output files or stdout only.

## Privacy

- No personal data is collected by the tool itself.
- Findings may contain identifiers from your Daml-LF (module names, template names, etc.). Treat scan outputs as sensitive if your source is sensitive.
- CI systems or external tooling may store logs/artifacts; review your CI retention policies.

If this policy changes, it will be documented here and in the release notes.
