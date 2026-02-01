# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json

from daml_sast.model import Finding


def compute_fingerprint(finding: Finding) -> str:
    span = None
    if finding.location.span:
        span = {
            "start_line": finding.location.span.start_line,
            "start_col": finding.location.span.start_col,
            "end_line": finding.location.span.end_line,
            "end_col": finding.location.span.end_col,
        }

    payload = {
        "id": finding.id,
        "module": finding.location.module,
        "definition": finding.location.definition,
        "span": span,
        "metadata": {k: finding.metadata[k] for k in sorted(finding.metadata)},
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
