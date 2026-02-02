import glob
import os
import subprocess
import sys
from pathlib import Path


def main(dar_glob: str, dar_dir: str, ignore_errors: bool) -> int:
    if not os.path.isdir(dar_dir):
        print(f"missing {dar_dir}; download DARs first")
        return 1

    dars = [p for p in glob.glob(dar_glob) if os.path.exists(p)]
    if not dars:
        print(f"no .dar files found for {dar_glob}")
        return 1

    errors = 0
    for dar in dars:
        print(f"scanning {dar}")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "daml_sast.cli",
                "scan",
                "--dar",
                dar,
                "--format",
                "json",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.stdout:
            print(result.stdout.strip())
        if result.returncode != 0:
            errors += 1
            print(f"scan failed: {dar}")

    if errors:
        print(f"{errors} DAR(s) failed")
        if not ignore_errors:
            return 1
    return 0


if __name__ == "__main__":
    # argv: [script, dar_glob, dar_dir, ignore_errors_flag]
    dar_glob_arg = sys.argv[1] if len(sys.argv) > 1 else "testdata/external/dars/*.dar"
    dar_dir_arg = sys.argv[2] if len(sys.argv) > 2 else "testdata/external/dars"
    ignore_errors_flag = sys.argv[3] if len(sys.argv) > 3 else "0"
    sys.exit(main(dar_glob_arg, dar_dir_arg, ignore_errors_flag == "1"))
