# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

from daml_sast.ir.model import Location


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class Evidence:
    kind: str
    note: str
    lf_ref: Optional[str] = None


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    message: str
    location: Location
    evidence: list[Evidence] = field(default_factory=list)
    related: list[Location] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    fingerprint: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)
