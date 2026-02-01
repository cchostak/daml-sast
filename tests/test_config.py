# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from daml_sast.config import load_config
from daml_sast.model import Severity


class ConfigTests(unittest.TestCase):
    def test_load_config(self) -> None:
        content = """
[scanner]
format = "sarif"
severity = "MEDIUM"
fail_on = "HIGH"
ci = true

[rules]
allow = ["DAML-AUTH-001"]
deny = "DAML-PRIV-001"

[baseline]
path = "baseline.json"
write = true
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "daml-sast.toml"
            path.write_text(content, encoding="utf-8")
            cfg = load_config(str(path))

        self.assertIsNotNone(cfg)
        assert cfg is not None
        self.assertEqual(cfg.fmt, "sarif")
        self.assertEqual(cfg.min_severity, Severity.MEDIUM)
        self.assertEqual(cfg.fail_on, Severity.HIGH)
        self.assertEqual(cfg.rule_allowlist, {"DAML-AUTH-001"})
        self.assertEqual(cfg.rule_denylist, {"DAML-PRIV-001"})
        self.assertEqual(cfg.baseline, "baseline.json")
        self.assertEqual(cfg.write_baseline, "baseline.json")
        self.assertTrue(cfg.ci)


if __name__ == "__main__":
    unittest.main()
