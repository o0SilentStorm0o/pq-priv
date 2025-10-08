#!/usr/bin/env python3
"""Write SHA256 sums for files in a directory."""
from __future__ import annotations

import argparse
import hashlib
import pathlib


def compute_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path, help="Directory to scan")
    args = parser.parse_args()

    directory = args.directory
    if not directory.exists() or not directory.is_dir():
        raise SystemExit(f"{directory} is not a directory")

    output = directory / "SHA256SUMS"
    with output.open("w", encoding="utf-8") as sink:
        for entry in sorted(directory.iterdir()):
            if entry == output or entry.is_dir():
                continue
            sink.write(f"{compute_sha256(entry)}  {entry.name}\n")


if __name__ == "__main__":
    main()
