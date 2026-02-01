from __future__ import annotations

import os
from typing import Optional


def find_newest_dar(root: str) -> Optional[str]:
    newest_path: Optional[str] = None
    newest_mtime = -1.0
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            if not name.endswith(".dar"):
                continue
            path = os.path.join(dirpath, name)
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if mtime > newest_mtime:
                newest_mtime = mtime
                newest_path = path
    return newest_path
