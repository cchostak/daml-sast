"""
Download DAR fixtures into a target directory.

Sources can come from:
- A manifest file (default: testdata/external/dars.manifest) with lines:
    <url> [filename] [sha256]
  Blank lines and lines starting with # are ignored.
- A space-separated list of URLs passed via --urls (or DAR_SOURCES in Make).
"""

import argparse
import hashlib
import os
import shutil
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


def parse_manifest(path: Path) -> List[Tuple[str, Optional[str], Optional[str]]]:
    if not path.exists():
        return []
    entries: List[Tuple[str, Optional[str], Optional[str]]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 1:
            url, filename, sha = parts[0], None, None
        elif len(parts) == 2:
            url, filename, sha = parts[0], parts[1], None
        else:
            url, filename, sha = parts[0], parts[1], parts[2]
        entries.append((url, filename, sha))
    return entries


def parse_urls(urls: str) -> List[Tuple[str, Optional[str], Optional[str]]]:
    clean = urls.strip()
    if not clean:
        return []
    return [(u, None, None) for u in clean.split()]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def download(url: str, dest: Path) -> None:
    """Download from HTTP/HTTPS or copy from local path/file://."""
    dest_tmp = dest.with_suffix(dest.suffix + ".tmp")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in ("file", "local", ""):
        # Local copy
        src_path = Path(parsed.path if parsed.scheme else url.replace("local:", "", 1)).resolve()
        if not src_path.exists():
            raise FileNotFoundError(src_path)
        shutil.copyfile(src_path, dest_tmp)
    else:
        with urllib.request.urlopen(url) as resp, dest_tmp.open("wb") as f:
            f.write(resp.read())
    dest_tmp.replace(dest)


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", dest="directory", required=True)
    parser.add_argument("--manifest", dest="manifest", default="testdata/external/dars.manifest")
    parser.add_argument("--urls", dest="urls", default="")
    args = parser.parse_args(list(argv))

    target_dir = Path(args.directory)
    manifest_entries = parse_manifest(Path(args.manifest))
    url_entries = parse_urls(args.urls)
    sources = manifest_entries + url_entries

    if not sources:
        print("No DAR sources specified.")
        print(f"Add entries to {args.manifest} or pass DAR_SOURCES=\"<url ...>\" to make fetch-dars.")
        return 1

    ensure_dir(target_dir)
    failures = 0
    successes = 0

    for url, filename, sha in sources:
        name = filename or Path(urllib.parse.urlparse(url).path).name
        dest = target_dir / name
        try:
            print(f"fetching {url} -> {dest}")
            download(url, dest)
            if sha:
                actual = sha256_file(dest)
                if actual.lower() != sha.lower():
                    raise ValueError(f"sha256 mismatch for {dest}: expected {sha}, got {actual}")
            successes += 1
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"failed: {url} ({exc})")

    if failures:
        print(f"{failures} download(s) failed")
        if successes == 0:
            return 1

    print(f"done ({successes} fetched)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
