# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from importlib import metadata


def get_version(default: str = "0.0.1") -> str:
    try:
        return metadata.version("daml-sast")
    except metadata.PackageNotFoundError:
        return default
