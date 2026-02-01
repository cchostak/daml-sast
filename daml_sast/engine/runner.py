# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from daml_sast.ir.model import Program
from daml_sast.model import Finding
from daml_sast.rules.base import Rule
from daml_sast.util.fingerprint import compute_fingerprint
from daml_sast.walker.walk import walk_program


def run(rules: Iterable[Rule], program: Program) -> list[Finding]:
    findings: list[Finding] = []

    def emit(f: Finding) -> None:
        findings.append(f)

    walk_program(program, rules, emit)
    finalized: list[Finding] = []
    for f in findings:
        if f.fingerprint:
            finalized.append(f)
            continue
        finalized.append(replace(f, fingerprint=compute_fingerprint(f)))
    return finalized
