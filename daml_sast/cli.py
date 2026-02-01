from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from typing import Iterable

from daml_sast.config import load_config
from daml_sast.engine.runner import run
from daml_sast.lf.loader import load_program_from_dar
from daml_sast.report.json_report import emit_json
from daml_sast.report.sarif_report import SarifContext, emit_sarif
from daml_sast.model import Severity
from daml_sast.rules.registry import filter_rules, registry
from daml_sast.util.baseline import load_baseline, write_baseline
from daml_sast.util.fs import find_newest_dar


def _parse_ids(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {v.strip() for v in value.split(",") if v.strip()}


def _severity_order(sev: Severity) -> int:
    order = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return order[sev]


def _parse_severity(value: str | None) -> Severity | None:
    if not value:
        return None
    value = value.upper()
    return Severity[value]


def _filter_by_severity(findings, minimum: Severity | None):
    if minimum is None:
        return list(findings)
    return [f for f in findings if _severity_order(f.severity) >= _severity_order(minimum)]


def _build_project(project: str) -> None:
    try:
        subprocess.run(["daml", "build"], cwd=project, check=True)
    except FileNotFoundError:
        return


def _resolve_dar(dar: str | None, project: str | None, no_build: bool) -> str:
    if dar:
        return dar
    if not project:
        raise ValueError("--dar or --project is required")
    if not no_build:
        _build_project(project)
    dar_path = find_newest_dar(project)
    if not dar_path:
        raise ValueError("No .dar found under project path")
    return dar_path


def _emit(findings, fmt: str, out_path: str | None, *, rule_meta=None, context=None) -> None:
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            if fmt == "json":
                emit_json(findings, f)
            elif fmt == "sarif":
                emit_sarif(findings, f, rule_meta=rule_meta, context=context)
            else:
                raise ValueError("--format must be json or sarif when --out is used")
    else:
        if fmt in ("json", "both"):
            emit_json(findings, sys.stdout)
        if fmt in ("sarif", "both"):
            emit_sarif(findings, sys.stdout, rule_meta=rule_meta, context=context)


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


def _exit_code(findings, fail_on: Severity | None) -> int:
    if fail_on is None:
        return EXIT_OK
    threshold = _severity_order(fail_on)
    for f in findings:
        if _severity_order(f.severity) >= threshold:
            return EXIT_FINDINGS
    return EXIT_OK


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="daml-sast")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a DAR or project")
    scan.add_argument("--config", help="Path to config TOML")
    scan.add_argument("--dar", help="Path to .dar file")
    scan.add_argument("--project", help="Path to Daml project")
    scan.add_argument("--no-build", action="store_true", help="Do not run 'daml build'")
    scan.add_argument("--out", help="Output file (default: stdout)")
    scan.add_argument("--format", choices=["json", "sarif", "both"])
    scan.add_argument("--rules", help="Comma-separated allowlist of rule IDs")
    scan.add_argument("--exclude", help="Comma-separated denylist of rule IDs")
    scan.add_argument("--severity", help="Minimum severity to report")
    scan.add_argument("--fail-on", help="Exit non-zero if findings >= level")
    scan.add_argument("--baseline", help="Path to baseline JSON to suppress findings")
    scan.add_argument("--write-baseline", help="Write baseline JSON to path")
    scan.add_argument("--ci", action="store_true", help="Emit CI-oriented metadata")

    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command != "scan":
        return EXIT_USAGE

    try:
        cfg = load_config(args.config)
    except Exception as exc:
        print(f"error: failed to load config: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        dar_path = _resolve_dar(args.dar, args.project, args.no_build)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    allow = _merge_set(_parse_ids(args.rules), cfg.rule_allowlist if cfg else None)
    deny = _merge_set(_parse_ids(args.exclude), cfg.rule_denylist if cfg else None)
    min_sev = _merge_val(_parse_severity(args.severity), cfg.min_severity if cfg else None)
    fail_on = _merge_val(_parse_severity(args.fail_on), cfg.fail_on if cfg else None)
    fmt = _merge_val(args.format, cfg.fmt if cfg else None) or "json"
    ci = args.ci if args.ci else bool(cfg.ci) if cfg and cfg.ci is not None else False
    baseline_path = args.baseline or (cfg.baseline if cfg else None)
    write_baseline_path = args.write_baseline or (cfg.write_baseline if cfg else None)
    if ci and fail_on is None:
        fail_on = Severity.MEDIUM

    try:
        program = load_program_from_dar(dar_path)
    except (NotImplementedError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    rules = filter_rules(registry(), allow, deny)
    rule_meta = {r.meta.id: r.meta for r in rules}
    start_time = datetime.now(timezone.utc)
    findings = run(rules, program)
    all_fingerprints = [f.fingerprint for f in findings if f.fingerprint]
    if write_baseline_path:
        write_baseline(write_baseline_path, all_fingerprints)

    findings = _filter_by_severity(findings, min_sev)
    if baseline_path:
        try:
            suppressed = load_baseline(baseline_path)
        except Exception as exc:
            print(f"error: failed to load baseline: {exc}", file=sys.stderr)
            return EXIT_USAGE
        findings = [f for f in findings if f.fingerprint not in suppressed]

    end_time = datetime.now(timezone.utc)
    context = SarifContext(
        command_line=" ".join(shlex.quote(a) for a in (argv or sys.argv)),
        cwd=os.getcwd(),
        ci=ci,
        start_time=start_time,
        end_time=end_time,
    )

    _emit(findings, fmt, args.out, rule_meta=rule_meta, context=context)
    return _exit_code(findings, fail_on)


def _merge_set(primary: set[str] | None, fallback: set[str] | None) -> set[str] | None:
    return primary if primary is not None else fallback


def _merge_val(primary, fallback):
    return primary if primary is not None else fallback


if __name__ == "__main__":
    raise SystemExit(main())
