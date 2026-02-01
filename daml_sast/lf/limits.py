# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class LfLimits:
    max_dar_bytes: int
    max_dar_uncompressed_bytes: int
    max_dar_entries: int
    max_dalf_bytes: int
    max_archive_payload_bytes: int
    max_package_bytes: int
    max_proto_depth: int
    max_proto_nodes: int


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return value


def limits() -> LfLimits:
    return LfLimits(
        max_dar_bytes=_env_int("DAML_SAST_MAX_DAR_BYTES", 200 * 1024 * 1024),
        max_dar_uncompressed_bytes=_env_int(
            "DAML_SAST_MAX_DAR_UNCOMPRESSED_BYTES", 300 * 1024 * 1024
        ),
        max_dar_entries=_env_int("DAML_SAST_MAX_DAR_ENTRIES", 2048),
        max_dalf_bytes=_env_int("DAML_SAST_MAX_DALF_BYTES", 50 * 1024 * 1024),
        max_archive_payload_bytes=_env_int(
            "DAML_SAST_MAX_ARCHIVE_PAYLOAD_BYTES", 50 * 1024 * 1024
        ),
        max_package_bytes=_env_int("DAML_SAST_MAX_PACKAGE_BYTES", 50 * 1024 * 1024),
        max_proto_depth=_env_int("DAML_SAST_MAX_PROTO_DEPTH", 200),
        max_proto_nodes=_env_int("DAML_SAST_MAX_PROTO_NODES", 500_000),
    )
