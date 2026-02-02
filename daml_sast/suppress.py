# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from daml_sast.model import Finding


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    module: Optional[str] = None
    definition: Optional[str] = None
    fingerprint: Optional[str] = None


def load_suppressions(path: str | None) -> list[Suppression]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    suppressions: list[Suppression] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "#" in stripped:
            stripped = stripped.split("#", 1)[0].strip()
        parts = stripped.split()
        if not parts:
            continue
        # rule_id [module] [definition] [fingerprint]
        rule_id = parts[0]
        module = parts[1] if len(parts) > 1 else None
        definition = parts[2] if len(parts) > 2 else None
        fingerprint = parts[3] if len(parts) > 3 else None
        suppressions.append(Suppression(rule_id, module, definition, fingerprint))
    return suppressions


def _match(val: str | None, pattern: str | None) -> bool:
    if pattern is None:
        return True
    if val is None:
        return False
    return fnmatch.fnmatchcase(val, pattern)


def is_suppressed(finding: Finding, suppressions: Iterable[Suppression]) -> bool:
    for sup in suppressions:
        if sup.rule_id != finding.id:
            continue
        if not _match(finding.location.module if finding.location else None, sup.module):
            continue
        if not _match(finding.location.definition if finding.location else None, sup.definition):
            continue
        if sup.fingerprint and finding.fingerprint and sup.fingerprint != finding.fingerprint:
            continue
        return True
    return False


def apply_suppressions(findings: Iterable[Finding], suppressions: Iterable[Suppression]) -> list[Finding]:
    sups = list(suppressions)
    return [f for f in findings if not is_suppressed(f, sups)]
