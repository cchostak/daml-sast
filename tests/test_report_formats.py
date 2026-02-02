# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_sample_dars as gsd  # type: ignore
from daml_sast.engine.runner import run
from daml_sast.lf.loader import load_program_from_dar
from daml_sast.report.json_report import emit_json
from daml_sast.report.sarif_report import SarifContext, emit_sarif
from daml_sast.rules.registry import registry


def _make_dar(tmp_path: Path, name: str):
    archive = gsd._archive_from_package(gsd.build_pkg_with_findings())
    dar_path = tmp_path / name
    gsd._write_zip(dar_path, "rules.dalf", archive)
    return dar_path


def test_emit_json(tmp_path: Path) -> None:
    dar = _make_dar(tmp_path, "sample.dar")
    findings = run(registry(), load_program_from_dar(str(dar)))
    buf = io.StringIO()
    emit_json(findings, buf)
    out = buf.getvalue()
    assert out.startswith("[")
    assert '"id": "DAML-AUTH-001"' in out


def test_emit_sarif(tmp_path: Path) -> None:
    dar = _make_dar(tmp_path, "sample.dar")
    findings = run(registry(), load_program_from_dar(str(dar)))
    buf = io.StringIO()
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    ctx = SarifContext(command_line="test", cwd="/tmp", ci=False, start_time=now, end_time=now)
    emit_sarif(findings, buf, rule_meta={r.meta.id: r.meta for r in registry()}, context=ctx)
    out = buf.getvalue()
    assert '"version": "2.1.0"' in out
    assert '"rules"' in out
    assert '"DAML-AUTH-001"' in out
