from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

from daml_sast.model import Severity


@dataclass(frozen=True)
class Config:
    rule_allowlist: set[str] | None = None
    rule_denylist: set[str] | None = None
    min_severity: Severity | None = None
    fail_on: Severity | None = None
    baseline: str | None = None
    write_baseline: str | None = None
    fmt: str | None = None
    ci: bool | None = None


def load_config(path: str | None) -> Config | None:
    if not path:
        return None
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    rules = data.get("rules", {})
    scanner = data.get("scanner", {})
    baseline = data.get("baseline", {})
    write_val = baseline.get("write")
    write_path = None
    if isinstance(write_val, bool):
        if write_val:
            write_path = baseline.get("path")
    elif write_val is not None:
        write_path = str(write_val)

    return Config(
        rule_allowlist=_parse_ids(rules.get("allow")),
        rule_denylist=_parse_ids(rules.get("deny")),
        min_severity=_parse_severity(scanner.get("severity")),
        fail_on=_parse_severity(scanner.get("fail_on")),
        baseline=baseline.get("path"),
        write_baseline=write_path,
        fmt=scanner.get("format"),
        ci=_parse_bool(scanner.get("ci")),
    )


def _parse_ids(value: Any) -> set[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        items = [v.strip() for v in value.split(",") if v.strip()]
        return set(items) if items else None
    if isinstance(value, list):
        items = [str(v).strip() for v in value if str(v).strip()]
        return set(items) if items else None
    return None


def _parse_severity(value: Any) -> Severity | None:
    if value is None:
        return None
    return Severity[str(value).upper()]


def _parse_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
    return None
