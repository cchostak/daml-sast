from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from daml_sast.model import Finding
from daml_sast.rules.base import RuleMeta, Severity
from daml_sast.util.version import get_version


@dataclass(frozen=True)
class SarifContext:
    command_line: str
    cwd: str
    ci: bool
    start_time: datetime
    end_time: datetime


def _level(sev: Severity) -> str:
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    return "note"


def _to_utc(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def emit_sarif(
    findings: Iterable[Finding],
    out,
    *,
    rule_meta: dict[str, RuleMeta] | None = None,
    context: SarifContext | None = None,
) -> None:
    results = []
    rules = {}

    for f in findings:
        meta = rule_meta.get(f.id) if rule_meta else None
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": meta.description if meta else f.message},
                "help": {"text": meta.rationale if meta else f.message},
                "properties": {
                    "category": f.category,
                    "tags": list(meta.tags) if meta else [],
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                },
            }

        loc = None
        if f.location.span and f.location.span.file:
            span = f.location.span
            loc = {
                "physicalLocation": {
                    "artifactLocation": {"uri": span.file},
                    "region": {
                        "startLine": span.start_line or 1,
                        "startColumn": span.start_col or 1,
                        "endLine": span.end_line or span.start_line or 1,
                        "endColumn": span.end_col or span.start_col or 1,
                    },
                }
            }

        result = {
            "ruleId": f.id,
            "level": _level(f.severity),
            "message": {"text": f.message},
            "locations": [loc] if loc else [],
            "properties": {"confidence": f.confidence.value, **f.metadata},
        }
        if f.fingerprint:
            result["partialFingerprints"] = {"damlSast/v1": f.fingerprint}
        results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": "daml-sast",
                "version": get_version(),
                "informationUri": "",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }

    if context:
        run["invocations"] = [
            {
                "commandLine": context.command_line,
                "executionSuccessful": True,
                "workingDirectory": {"uri": context.cwd},
                "startTimeUtc": _to_utc(context.start_time),
                "endTimeUtc": _to_utc(context.end_time),
            }
        ]
        run["properties"] = {"ci": context.ci}
        if context.ci:
            run["automationDetails"] = {"id": "daml-sast-ci"}

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    json.dump(sarif, out, indent=2)
    out.write("\n")
