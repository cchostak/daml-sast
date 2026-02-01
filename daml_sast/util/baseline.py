# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path

from daml_sast.rules.version import RULESET_VERSION
from daml_sast.util.version import get_version


def load_baseline(path: str) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        raise ValueError("Legacy baseline format is unsupported; regenerate the baseline")
    if isinstance(data, dict):
        tool_version = data.get("tool_version")
        rules_version = data.get("rules_version")
        if tool_version is None or rules_version is None:
            raise ValueError("Baseline missing version metadata; regenerate the baseline")
        current_tool = get_version()
        if tool_version != current_tool:
            raise ValueError(
                f"Baseline tool version {tool_version} does not match {current_tool}"
            )
        if rules_version != RULESET_VERSION:
            raise ValueError(
                f"Baseline rules version {rules_version} does not match {RULESET_VERSION}"
            )
        fingerprints = data.get("fingerprints", [])
        return {str(x) for x in fingerprints}
    return set()


def write_baseline(path: str, fingerprints: list[str]) -> None:
    payload = {
        "tool_version": get_version(),
        "rules_version": RULESET_VERSION,
        "fingerprints": fingerprints,
    }
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
