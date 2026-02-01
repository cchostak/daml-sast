# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class LfVersion:
    major: int
    minor: int
    patch: int | None = None

    def short(self) -> str:
        return f"{self.major}.{self.minor}"

    def full(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}" if self.patch is not None else self.short()


# Supported language versions. Update intentionally and keep tests in sync.
SUPPORTED_VERSIONS: set[str] = {
    # LF1
    "1.6",
    "1.7",
    "1.8",
    "1.11",
    "1.14",
    "1.15",
    "1.17",
    # LF2
    "2.1",
}


def normalize_version(major: int, minor_str: str | None, patch: int | None) -> LfVersion:
    if minor_str is None or minor_str == "":
        raise ValueError("Missing Daml-LF minor version")

    parts = minor_str.split(".")
    if len(parts) == 1:
        minor = int(parts[0])
        return LfVersion(major=major, minor=minor, patch=patch)

    if len(parts) == 2:
        major_part = int(parts[0])
        minor = int(parts[1])
        if major_part != major:
            raise ValueError(f"Version major mismatch: payload {major_part} vs envelope {major}")
        return LfVersion(major=major, minor=minor, patch=patch)

    raise ValueError(f"Unrecognized Daml-LF version format: {minor_str}")


def is_supported(version: LfVersion) -> bool:
    return version.short() in SUPPORTED_VERSIONS


def supported_versions() -> Iterable[str]:
    return sorted(SUPPORTED_VERSIONS, key=lambda v: [int(p) for p in v.split(".")])
