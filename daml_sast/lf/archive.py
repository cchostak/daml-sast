from __future__ import annotations

from dataclasses import dataclass
from typing import List
import zipfile


@dataclass(frozen=True)
class DalfEntry:
    path: str
    raw: bytes


def extract_dalf_entries(dar_path: str) -> List[DalfEntry]:
    entries: List[DalfEntry] = []
    with zipfile.ZipFile(dar_path, "r") as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".dalf"):
                continue
            entries.append(DalfEntry(path=info.filename, raw=zf.read(info)))
    return entries
