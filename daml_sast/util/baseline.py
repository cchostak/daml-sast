from __future__ import annotations

import json
from pathlib import Path


def load_baseline(path: str) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {str(x) for x in data}
    if isinstance(data, dict):
        fingerprints = data.get("fingerprints", [])
        return {str(x) for x in fingerprints}
    return set()


def write_baseline(path: str, fingerprints: list[str]) -> None:
    payload = {
        "fingerprints": fingerprints,
    }
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
