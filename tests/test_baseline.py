# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from daml_sast.util.baseline import load_baseline, write_baseline


class BaselineTests(unittest.TestCase):
    def test_write_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            write_baseline(str(path), ["a", "b"])
            loaded = load_baseline(str(path))
        self.assertEqual(loaded, {"a", "b"})

    def test_rejects_missing_version_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text('{"fingerprints": ["a"]}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(str(path))


if __name__ == "__main__":
    unittest.main()
