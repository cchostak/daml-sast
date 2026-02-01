# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from daml_sast.ir.model import Program
from daml_sast.ir.lower import lower_packages
from daml_sast.lf.archive import extract_dalf_entries
from daml_sast.lf.decoder import decode_dalf


def load_program_from_dar(path: str) -> Program:
    entries = extract_dalf_entries(path)
    if not entries:
        raise ValueError("No .dalf entries found in DAR")
    packages = [decode_dalf(entry) for entry in entries]
    return lower_packages(packages)
