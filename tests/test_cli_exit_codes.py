# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from daml_sast.cli import _exit_code
from daml_sast.model import Confidence, Finding, Location, Severity


def _finding(sev: Severity) -> Finding:
    return Finding(
        id="X",
        title="t",
        severity=sev,
        confidence=Confidence.MEDIUM,
        category="c",
        message="m",
        location=Location(module="M", definition="D"),
        evidence=[],
        related=[],
        metadata={},
        fingerprint=None,
    )


def test_exit_code_none_threshold() -> None:
    assert _exit_code([_finding(Severity.CRITICAL)], None) == 0


def test_exit_code_below_threshold() -> None:
    assert _exit_code([_finding(Severity.LOW)], Severity.HIGH) == 0


def test_exit_code_at_threshold() -> None:
    assert _exit_code([_finding(Severity.HIGH)], Severity.HIGH) == 1
