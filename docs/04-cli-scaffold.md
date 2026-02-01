# CLI Entrypoint Scaffold

Facts:
- Tool must accept a .dar file.

Assumptions:
- If a project path is provided, the tool can attempt `daml build` if the Daml CLI is available.
- If build output location is unknown, the tool searches for the newest .dar under the project directory.

## CLI Outline

Command name (example): `daml-sast`

```text
Usage:
  daml-sast scan --dar <path> [options]
  daml-sast scan --project <path> [options]

Options:
  --dar <path>           Path to .dar file
  --project <path>       Path to Daml project (runs build if needed)
  --out <path>           Output file (default: stdout)
  --format <f>           json | sarif | both (default: json)
  --rules <ids>          Comma-separated allowlist of rule IDs
  --exclude <ids>        Comma-separated denylist of rule IDs
  --severity <level>     Minimum severity to report
  --fail-on <level>      Exit non-zero if findings >= level
  --timings              Emit timing info to stderr
  --debug                Verbose logging
```

## Pseudocode (Rust-style)

```text
fn main() -> ExitCode {
  let args = parse_args();
  let dar_path = if args.dar.is_some() {
    args.dar
  } else if args.project.is_some() {
    build_or_find_dar(args.project)
  } else {
    error("--dar or --project required");
  };

  let lf_packages = lf::load_packages(dar_path)?;
  let ir_program = ir::lower(lf_packages)?;

  let rules = rules::registry();
  let rules = rules::filter(rules, args.rules, args.exclude);

  let findings = engine::run(rules, ir_program)?;
  let findings = report::filter_by_severity(findings, args.severity);

  report::emit(findings, args.format, args.out)?;
  return exit_code_from(findings, args.fail_on);
}
```

## `build_or_find_dar` sketch

```text
fn build_or_find_dar(project_path) -> Path {
  if daml_cli_exists() {
    run("daml build", project_path)
  }
  // Search for the newest .dar under the project directory
  // to avoid hardcoding dist paths.
  find_newest_file(project_path, "*.dar")
}
```

Notes:
- Fail fast if multiple .dar files are found and none is clearly newest.
- Daml-LF loading should not depend on ledger; it should read the DAR archive.
