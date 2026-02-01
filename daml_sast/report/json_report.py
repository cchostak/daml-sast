from __future__ import annotations

import json
from typing import Iterable, TextIO

from daml_sast.model import Finding


def emit_json(findings: Iterable[Finding], out: TextIO) -> None:
    payload = [f.to_dict() for f in findings]
    json.dump(payload, out, indent=2)
    out.write("\n")
