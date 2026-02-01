# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from daml_sast.lf.archive import extract_dalf_entries


class LfLimitsTests(unittest.TestCase):
    def test_rejects_oversized_dalf_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dar_path = Path(tmp) / "big.dar"
            with zipfile.ZipFile(dar_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("big.dalf", b"x" * 32)

            old = os.environ.get("DAML_SAST_MAX_DALF_BYTES")
            os.environ["DAML_SAST_MAX_DALF_BYTES"] = "16"
            try:
                with self.assertRaises(ValueError):
                    extract_dalf_entries(str(dar_path))
            finally:
                if old is None:
                    os.environ.pop("DAML_SAST_MAX_DALF_BYTES", None)
                else:
                    os.environ["DAML_SAST_MAX_DALF_BYTES"] = old


if __name__ == "__main__":
    unittest.main()
