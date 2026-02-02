# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

from daml_sast.model import Confidence, Finding, Location, Severity
from daml_sast.suppress import apply_suppressions, load_suppressions


def _finding(rule: str, module: str = "Main", definition: str = "Choice X", fp: str | None = None) -> Finding:
    return Finding(
        id=rule,
        title="t",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="c",
        message="m",
        location=Location(module=module, definition=definition),
        evidence=[],
        related=[],
        metadata={},
        fingerprint=fp,
    )


def test_apply_suppressions_match_rule_and_module(tmp_path: Path) -> None:
    sup_file = tmp_path / ".daml-sast-ignore"
    sup_file.write_text("DAML-AUTH-002 Main *\n", encoding="utf-8")
    suppressions = load_suppressions(str(sup_file))
    findings = [_finding("DAML-AUTH-002"), _finding("DAML-LIFE-001")]
    kept = apply_suppressions(findings, suppressions)
    assert [f.id for f in kept] == ["DAML-LIFE-001"]


def test_apply_suppressions_requires_rule_match(tmp_path: Path) -> None:
    sup_file = tmp_path / ".daml-sast-ignore"
    sup_file.write_text("DAML-AUTH-003\n", encoding="utf-8")
    suppressions = load_suppressions(str(sup_file))
    findings = [_finding("DAML-AUTH-002")]
    kept = apply_suppressions(findings, suppressions)
    assert len(kept) == 1


def test_apply_suppressions_with_fingerprint(tmp_path: Path) -> None:
    sup_file = tmp_path / ".daml-sast-ignore"
    sup_file.write_text("DAML-AUTH-002 * * deadbeef\n", encoding="utf-8")
    suppressions = load_suppressions(str(sup_file))
    f1 = _finding("DAML-AUTH-002", fp="deadbeef")
    f2 = _finding("DAML-AUTH-002", fp="cafebabe")
    kept = apply_suppressions([f1, f2], suppressions)
    assert [f.fingerprint for f in kept] == ["cafebabe"]
