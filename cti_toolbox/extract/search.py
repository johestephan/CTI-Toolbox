"""Blacklist / Indicator file search utility.

Searches directory files (e.g. blocklists, indicator feeds) for a specific IOC or pattern.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def getFiles(text: str, search_dir: str | Path = "./bl") -> list[str]:
    """Search for string within all files in a directory."""
    matched_files: list[str] = []
    target_dir = Path(search_dir)

    if not target_dir.is_dir():
        return matched_files

    for entry in target_dir.iterdir():
        if entry.is_file():
            try:
                with open(entry, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if text in line:
                            matched_files.append(str(entry))
                            print(f"Found '{text}' in file: {entry}")
                            break
            except Exception as e:
                sys.stderr.write(f"Error reading {entry}: {e}\n")

    return matched_files


def search_indicators(pattern: str, search_dir: str | Path = ".") -> dict[str, list[str]]:
    """Detailed search across directory returning filename to matching line mappings."""
    results: dict[str, list[str]] = {}
    target_dir = Path(search_dir)

    if not target_dir.exists():
        return results

    files_to_check = [target_dir] if target_dir.is_file() else [p for p in target_dir.rglob("*") if p.is_file()]

    for file_path in files_to_check:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                matches: list[str] = []
                for lineno, line in enumerate(f, 1):
                    if pattern in line:
                        matches.append(f"L{lineno}: {line.strip()}")
                if matches:
                    results[str(file_path)] = matches
        except Exception:
            continue

    return results


def main() -> None:
    """CLI entry point for indicator search."""
    parser = argparse.ArgumentParser(description="Search blocklist / feed files for an indicator or pattern.")
    parser.add_argument("indicator", help="String or indicator to search for")
    parser.add_argument("-d", "--dir", default=".", help="Directory to search (default: current directory)")

    args = parser.parse_args()
    matches = getFiles(args.indicator, args.dir)
    if not matches:
        print(f"Indicator '{args.indicator}' not found in '{args.dir}'")


if __name__ == "__main__":
    main()
