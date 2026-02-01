# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Iterable

from daml_sast.rules.base import Rule
from daml_sast.rules.examples import (
    AuthControllerAlignmentRule,
    DeterminismTimeRule,
    KeyMaintainersAlignmentRule,
    NonconsumingCreateRule,
    OverbroadObserversRule,
)


def registry() -> list[Rule]:
    return [
        AuthControllerAlignmentRule(),
        NonconsumingCreateRule(),
        OverbroadObserversRule(),
        KeyMaintainersAlignmentRule(),
        DeterminismTimeRule(),
    ]


def filter_rules(
    rules: Iterable[Rule], allowlist: set[str] | None, denylist: set[str] | None
) -> list[Rule]:
    allow = allowlist or set()
    deny = denylist or set()
    filtered: list[Rule] = []
    for rule in rules:
        if allow and rule.meta.id not in allow:
            continue
        if rule.meta.id in deny:
            continue
        filtered.append(rule)
    return filtered
