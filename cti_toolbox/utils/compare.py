"""File comparison and overlap analysis tool for threat feeds and indicator lists."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_STOPWORDS = {"is", "of", "to", "and", "the", "or", "in", "a", "an", "on", "for", "with", "by", "at"}


def compare_files(
    file1_path: str | Path,
    file2_path: str | Path,
    stopwords: set[str] | None = None,
    min_word_matches: int = 1,
    verbose: bool = True,
) -> dict[str, int]:
    """Compare two text/feed files for line and token overlap."""
    if stopwords is None:
        stopwords = DEFAULT_STOPWORDS

    f1 = Path(file1_path)
    f2 = Path(file2_path)

    if not f1.is_file():
        raise FileNotFoundError(f"File not found: {f1}")
    if not f2.is_file():
        raise FileNotFoundError(f"File not found: {f2}")

    with open(f1, "r", encoding="utf-8", errors="replace") as fh1:
        f1_lines = [line.strip() for line in fh1 if line.strip()]

    with open(f2, "r", encoding="utf-8", errors="replace") as fh2:
        f2_lines = [line.strip() for line in fh2 if line.strip()]

    total_matches = 0
    total_f1_lines = len(f1_lines)

    for line1 in f1_lines:
        words1 = [w.lower().strip() for w in line1.split() if w.lower().strip() not in stopwords]
        if not words1:
            continue

        for line2 in f2_lines:
            line2_lower = line2.lower()
            match_count = sum(1 for word in words1 if word in line2_lower)

            if match_count >= min_word_matches:
                total_matches += 1
                if verbose:
                    print(f"[{match_count} match(es)] {line1}  <===>  {line2}")

    return {
        "file1_lines": total_f1_lines,
        "file2_lines": len(f2_lines),
        "matches": total_matches,
    }


def main() -> None:
    """CLI interface for compare."""
    parser = argparse.ArgumentParser(description="Compare two indicator / log files for token overlap.")
    parser.add_argument("file1", help="First file to compare")
    parser.add_argument("file2", help="Second file to compare")
    parser.add_argument("-m", "--min-matches", type=int, default=1, help="Minimum matching words required (default: 1)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode: show only summary statistics")

    args = parser.parse_args()

    try:
        stats = compare_files(
            args.file1,
            args.file2,
            min_word_matches=args.min_matches,
            verbose=not args.quiet,
        )
        print("\n--- Summary ---")
        print(f"File 1: {args.file1} ({stats['file1_lines']} lines)")
        print(f"File 2: {args.file2} ({stats['file2_lines']} lines)")
        print(f"Total Matches: {stats['matches']}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
