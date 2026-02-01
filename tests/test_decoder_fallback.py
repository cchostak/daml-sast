# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import unittest
from unittest import mock

from daml_sast.lf.archive import DalfEntry
from daml_sast.lf.decoder import ProtoDecodeError, decode_dalf
from daml_sast.lf.proto.com.digitalasset.daml.lf.archive import (
    daml_lf2_pb2,
    daml_lf_pb2,
)


class DecoderFallbackTests(unittest.TestCase):
    def test_lf1_payload_with_lf2_package_fallback(self) -> None:
        pkg = _build_minimal_lf2_package(name="daml-prim")
        payload = daml_lf_pb2.ArchivePayload()
        payload.minor = "14"
        payload.patch = 0
        payload.daml_lf_1 = pkg.SerializeToString()

        payload_bytes = payload.SerializeToString()
        archive = daml_lf_pb2.Archive()
        archive.hash_function = daml_lf_pb2.SHA256
        archive.payload = payload_bytes
        archive.hash = hashlib.sha256(payload_bytes).hexdigest()

        entry = DalfEntry(path="daml-prim.dalf", raw=archive.SerializeToString())
        with mock.patch(
            "daml_sast.lf.decoder._decode_lf1_package",
            side_effect=ProtoDecodeError("lf1 decode failed"),
        ):
            decoded = decode_dalf(entry)

        self.assertEqual(decoded.lf_major, 2)
        self.assertEqual(decoded.lf_version, "2.1")
        self.assertEqual(decoded.name, "daml-prim")


def _build_minimal_lf2_package(name: str) -> daml_lf2_pb2.Package:
    pkg = daml_lf2_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    s_idx("Main")
    s_idx(name)
    s_idx("0.0.0")
    pkg.interned_strings.extend(strings)

    dname = pkg.interned_dotted_names.add()
    dname.segments_interned_str.extend([s_idx("Main")])

    pkg.metadata.name_interned_str = s_idx(name)
    pkg.metadata.version_interned_str = s_idx("0.0.0")

    mod = pkg.modules.add()
    mod.name_interned_dname = 0
    return pkg


if __name__ == "__main__":
    unittest.main()
