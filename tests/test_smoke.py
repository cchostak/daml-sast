from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from daml_sast.ir.model import Program
from daml_sast.lf.archive import extract_dalf_entries
from daml_sast.lf.archive import DalfEntry
from daml_sast.lf.decoder import ProtoDecodeError, decode_dalf
from daml_sast.lf.loader import load_program_from_dar

FIXTURE = Path(__file__).resolve().parent.parent / "testdata" / "minimal.dar"


class SmokeTests(unittest.TestCase):
    def test_decode_dalf_extracts_payload(self) -> None:
        entries = extract_dalf_entries(str(FIXTURE))
        self.assertEqual(len(entries), 1)

        pkg = decode_dalf(entries[0])
        self.assertEqual(pkg.lf_version, "2.1")
        self.assertGreater(len(pkg.package_bytes), 0)
        self.assertEqual(pkg.name, "TestPkg")
        self.assertEqual(pkg.version, "TestPkg")

        expected_hash = hashlib.sha256(pkg.archive_payload).hexdigest()
        self.assertEqual(pkg.package_id, expected_hash)

    def test_loader_pipeline(self) -> None:
        result = load_program_from_dar(str(FIXTURE))
        self.assertIsInstance(result, Program)
        self.assertEqual(len(result.packages), 1)

    def test_decoder_rejects_invalid_wire_type(self) -> None:
        # Truncated length-delimited field should fail to decode.
        # tag=(field=3, wire=2)=0x1a, length=5 but only 1 byte of payload.
        bad = DalfEntry(path="bad.dalf", raw=b"\x1a\x05\x00")
        with self.assertRaises(ProtoDecodeError):
            decode_dalf(bad)


if __name__ == "__main__":
    unittest.main()
