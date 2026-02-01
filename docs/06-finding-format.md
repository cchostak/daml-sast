# Finding Output Format (JSON + SARIF-ready)

## JSON (Single Finding Example)

```json
{
  "id": "DAML-AUTH-001",
  "title": "Controller not aligned with signatories",
  "severity": "MEDIUM",
  "confidence": "MEDIUM",
  "category": "auth",
  "message": "Choice controllers are not a subset of template signatories.",
  "location": {
    "module": "Main",
    "definition": "Template MyAsset",
    "span": {
      "file": "Main.daml",
      "start_line": 42,
      "start_col": 5,
      "end_line": 45,
      "end_col": 12
    }
  },
  "evidence": [
    {
      "kind": "choice",
      "note": "Choice Transfer controllers expression",
      "lf_ref": "pkg:abc123/mod:Main/choice:Transfer"
    }
  ],
  "related": [
    {
      "module": "Main",
      "definition": "Template MyAsset",
      "span": {
        "file": "Main.daml",
        "start_line": 20,
        "start_col": 5,
        "end_line": 22,
        "end_col": 12
      }
    }
  ],
  "metadata": {
    "template": "MyAsset",
    "choice": "Transfer"
  }
}
```

Notes:
- `span` is optional if not present in Daml-LF location metadata.
- `lf_ref` is an opaque reference to the underlying Daml-LF node.

## SARIF Mapping (Minimal)

```text
rule.id                <- Finding.id
rule.name              <- Finding.title
rule.shortDescription  <- Finding.title
rule.fullDescription   <- Finding.message
rule.properties.tags   <- Finding.category + tags
result.message.text    <- Finding.message
result.level           <- map_severity_to_sarif(Finding.severity)
result.locations[0]    <- Finding.location (if span present)
result.relatedLocations<- Finding.related
result.properties      <- Finding.metadata
```

Severity mapping suggestion:
- CRITICAL/HIGH -> "error"
- MEDIUM -> "warning"
- LOW -> "note"
