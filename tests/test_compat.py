from __future__ import annotations

import unittest

from daml_sast.lf.compat import LfVersion, normalize_version, supported_versions, is_supported


class CompatTests(unittest.TestCase):
    def test_supported_versions_matrix(self) -> None:
        for v in supported_versions():
            major, minor = (int(p) for p in v.split("."))
            self.assertTrue(is_supported(LfVersion(major=major, minor=minor)))
            normalized = normalize_version(major, str(minor), 0)
            self.assertEqual(normalized.short(), v)


if __name__ == "__main__":
    unittest.main()
