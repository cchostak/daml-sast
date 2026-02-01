# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List
import zipfile

from daml_sast.lf.limits import limits


@dataclass(frozen=True)
class DalfEntry:
    path: str
    raw: bytes


def extract_dalf_entries(dar_path: str) -> List[DalfEntry]:
    lim = limits()
    try:
        size = Path(dar_path).stat().st_size
    except OSError as exc:
        raise ValueError(f"Failed to read DAR: {exc}") from exc
    if size > lim.max_dar_bytes:
        raise ValueError(
            f"DAR size {size} exceeds max {lim.max_dar_bytes} bytes"
        )

    entries: List[DalfEntry] = []
    try:
        with zipfile.ZipFile(dar_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > lim.max_dar_entries:
                raise ValueError(
                    f"DAR contains {len(infos)} entries; max is {lim.max_dar_entries}"
                )
            total_uncompressed = 0
            for info in infos:
                total_uncompressed += info.file_size
                if total_uncompressed > lim.max_dar_uncompressed_bytes:
                    raise ValueError(
                        "DAR uncompressed size exceeds "
                        f"{lim.max_dar_uncompressed_bytes} bytes"
                    )
                if not info.filename.endswith(".dalf"):
                    continue
                if info.file_size > lim.max_dalf_bytes:
                    raise ValueError(
                        f"DALF entry {info.filename} size {info.file_size} exceeds "
                        f"max {lim.max_dalf_bytes} bytes"
                    )
                raw = _read_zip_limited(zf, info, lim.max_dalf_bytes)
                entries.append(DalfEntry(path=info.filename, raw=raw))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid DAR zip file: {exc}") from exc
    return entries


def _read_zip_limited(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with zf.open(info, "r") as fp:
        data = fp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Entry {info.filename} exceeds max size {limit} bytes")
    return data
