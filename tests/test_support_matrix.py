# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from daml_sast.lf.compat import supported_versions
from daml_sast.lf.loader import load_program_from_dar
from daml_sast.lf.proto.com.digitalasset.daml.lf.archive import (
    daml_lf1_pb2,
    daml_lf2_pb2,
    daml_lf_pb2,
)


class SupportMatrixTests(unittest.TestCase):
    def test_supported_lf_versions_load(self) -> None:
        lf1_pkg = _build_minimal_lf1_package()
        lf2_pkg = _build_minimal_lf2_package()
        with tempfile.TemporaryDirectory() as tmp:
            for version in supported_versions():
                major, minor = (int(part) for part in version.split("."))
                dar_path = Path(tmp) / f"lf{major}-{minor}.dar"
                if major == 1:
                    pkg_bytes = lf1_pkg.SerializeToString()
                    _write_dar(dar_path, pkg_bytes, major, minor)
                else:
                    pkg_bytes = lf2_pkg.SerializeToString()
                    _write_dar(dar_path, pkg_bytes, major, minor)
                program = load_program_from_dar(str(dar_path))
                self.assertTrue(program.packages, msg=f"Failed for LF {version}")


def _write_dar(path: Path, pkg_bytes: bytes, major: int, minor: int) -> None:
    payload = daml_lf_pb2.ArchivePayload()
    payload.minor = f"{major}.{minor}"
    payload.patch = 0
    if major == 1:
        payload.daml_lf_1 = pkg_bytes
    else:
        payload.daml_lf_2 = pkg_bytes

    payload_bytes = payload.SerializeToString()
    archive = daml_lf_pb2.Archive()
    archive.hash_function = daml_lf_pb2.SHA256
    archive.payload = payload_bytes
    archive.hash = hashlib.sha256(payload_bytes).hexdigest()

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"pkg-{major}-{minor}.dalf", archive.SerializeToString())


def _build_minimal_lf1_package() -> daml_lf1_pb2.Package:
    pkg = daml_lf1_pb2.Package()
    strings: list[str] = []
    string_idx: dict[str, int] = {}

    def s_idx(val: str) -> int:
        if val in string_idx:
            return string_idx[val]
        string_idx[val] = len(strings)
        strings.append(val)
        return string_idx[val]

    s_idx("Main")
    s_idx("TestPkg")
    s_idx("0.0.0")
    pkg.interned_strings.extend(strings)

    dname = pkg.interned_dotted_names.add()
    dname.segments_interned_str.extend([s_idx("Main")])

    pkg.metadata.name_interned_str = s_idx("TestPkg")
    pkg.metadata.version_interned_str = s_idx("0.0.0")

    mod = pkg.modules.add()
    mod.name_interned_dname = 0
    return pkg


def _build_minimal_lf2_package() -> daml_lf2_pb2.Package:
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
    s_idx("TestPkg")
    s_idx("0.0.0")
    pkg.interned_strings.extend(strings)

    dname = pkg.interned_dotted_names.add()
    dname.segments_interned_str.extend([s_idx("Main")])

    pkg.metadata.name_interned_str = s_idx("TestPkg")
    pkg.metadata.version_interned_str = s_idx("0.0.0")

    mod = pkg.modules.add()
    mod.name_interned_dname = 0
    return pkg


if __name__ == "__main__":
    unittest.main()
