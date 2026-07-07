#!/usr/bin/env python3
from __future__ import annotations

"""
File Integrity Monitoring (FIM) CLI — SHA-256 baseline auditing for log files.

Maps file paths to cryptographic hashes in a JSON baseline store and detects
unauthorized tampering via periodic verification.

Usage:
    python integrity_check.py init <path>
    python integrity_check.py check <path>
    python integrity_check.py update <path>
"""

import argparse
import fnmatch
import hashlib
import json
import os
import pathlib
import stat
import sys
import time

BASELINE_FILE: str = ".metadata_store.json"
CHUNK_SIZE: int = 4096

# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------

class Color:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def c(text: str, color: str) -> str:
    """Wrap *text* in ANSI color if stdout is a TTY; pass through otherwise.

    This ensures piped output (|, >, subprocess capture) stays plain-text
    while interactive terminals get readable colored output.
    """
    return f"{color}{text}{Color.RESET}" if sys.stdout.isatty() else text


def green(text: str) -> str:
    return c(text, Color.GREEN)


def red(text: str) -> str:
    return c(text, Color.RED)


def yellow(text: str) -> str:
    return c(text, Color.YELLOW)


def cyan(text: str) -> str:
    return c(text, Color.CYAN)


def bold(text: str) -> str:
    return c(text, Color.BOLD)


# ---------------------------------------------------------------------------
# Hashing engine
# ---------------------------------------------------------------------------

AVAILABLE_ALGORITHMS = sorted(hashlib.algorithms_guaranteed)


def sha256_file(path: pathlib.Path, algorithm: str = "sha256") -> str:
    """Compute hex digest of *path* using a streaming 4 KB buffer.

    Chunking at 4096 bytes is a deliberate memory-safety choice: a 16 GB log
    file is never fully loaded into RAM.  Only the rolling digest state (32
    bytes for SHA-256) is held between reads, making the routine safe for
    production systems with limited memory.
    """
    h = hashlib.new(algorithm)
    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(CHUNK_SIZE)
                if not block:
                    break
                h.update(block)
    except PermissionError:
        raise
    except OSError as e:
        raise OSError(f"Failed to read {path}: {e}") from e
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------

def load_baseline() -> tuple[dict, dict]:
    """Deserialise the JSON baseline store.

    Returns ``(hashes_dict, metadata_dict)``.  If the file is absent or
    corrupt both values are empty dicts.
    """
    p = pathlib.Path(BASELINE_FILE)
    if not p.exists():
        return {}, {}
    try:
        raw = p.read_text(encoding="utf-8")
        data: dict = json.loads(raw)
        metadata = data.pop("_metadata", {})
        return data, metadata
    except (json.JSONDecodeError, OSError) as e:
        print(f"{yellow('[WARN]')} Baseline file corrupt or unreadable ({e}); starting fresh.", file=sys.stderr)
        return {}, {}


def save_baseline(baseline: dict, metadata: dict = None) -> None:
    """Atomically write the baseline dict to *BASELINE_FILE*.

    An optional ``_metadata`` dict is merged at the top level (algorithm name,
    creation time, etc.).
    """
    data = dict(baseline)
    if metadata:
        data["_metadata"] = metadata
    tmp = pathlib.Path(BASELINE_FILE + ".tmp")
    tmp.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    tmp.replace(BASELINE_FILE)


# ---------------------------------------------------------------------------
# File discovery helpers
# ---------------------------------------------------------------------------

def _resolve_path(raw: str) -> pathlib.Path:
    """Resolve user-supplied path, expanding ~ and symlinks."""
    return pathlib.Path(raw).expanduser().resolve()


def _iter_log_files(root: pathlib.Path, exclude_patterns: list[str] | None = None):
    """Recursively yield regular files under *root* (or *root* itself if it is a file).

    Symlinks are intentionally skipped — following them could escape the
    intended audit boundary and create double-counting or TOCTOU issues.
    Files whose *name* matches any ``exclude_patterns`` glob are skipped.
    Also silently skips the baseline store itself to avoid self-referencing.
    """
    exclude = exclude_patterns or []
    if root.is_file():
        yield root
        return

    for entry in root.rglob("*"):
        if entry.name == BASELINE_FILE:
            continue
        if any(fnmatch.fnmatch(entry.name, pat) for pat in exclude):
            continue
        try:
            st = entry.lstat()
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            yield entry


def _collect_hashes(root: pathlib.Path, algorithm: str = "sha256", exclude_patterns: list[str] | None = None) -> dict:
    """Walk *root* and return ``{str(path): str(digest)}``.

    Permission-denied files are reported to stderr and skipped.
    """
    result: dict[str, str] = {}
    for fp in _iter_log_files(root, exclude_patterns):
        try:
            digest = sha256_file(fp, algorithm)
            result[str(fp)] = digest
        except PermissionError:
            print(f"{yellow('[SKIP]')}  Permission denied: {fp}", file=sys.stderr)
        except OSError as e:
            print(f"{yellow('[SKIP]')}  {e}", file=sys.stderr)
    return result


# ---------------------------------------------------------------------------
# CLI actions
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    """Initialise a new baseline by hashing every file under *path*."""
    root = _resolve_path(args.path)
    if not root.exists():
        print(f"{red('[FAIL]')}  Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    baseline = _collect_hashes(root, algorithm=args.algorithm, exclude_patterns=args.exclude)
    if not baseline:
        print(f"{yellow('[WARN]')}  No files found — baseline will be empty.", file=sys.stderr)

    metadata = {
        "algorithm": args.algorithm,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    save_baseline(baseline, metadata)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"{green('[ OK ]')}  Baseline initialised: {cyan(str(len(baseline)))} files hashed  ({ts})")


def cmd_check(args: argparse.Namespace) -> None:
    """Compare current file hashes against the stored baseline.

    Each file is classified as *Unmodified*, *Modified*, or *Missing*.
    """
    baseline, metadata = load_baseline()
    if not baseline:
        print(f"{red('[FAIL]')}  No baseline found. Run 'init' first.", file=sys.stderr)
        sys.exit(1)

    algorithm = metadata.get("algorithm", "sha256")
    root = _resolve_path(args.path)
    if not root.exists():
        print(f"{red('[FAIL]')}  Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    modified_count = 0
    missing_count = 0
    unmodified_count = 0

    current = _collect_hashes(root, algorithm=algorithm, exclude_patterns=args.exclude)

    results: list[dict] = []
    all_paths = set(baseline.keys()) | set(current.keys())
    for path_str in sorted(all_paths):
        if path_str in baseline and path_str not in current:
            results.append({"file": path_str, "status": "missing"})
            if not args.json:
                print(f"{yellow('[MISS]')}  {path_str}")
            missing_count += 1
            continue
        if path_str not in baseline:
            continue

        old = baseline[path_str]
        new = current[path_str]
        if old == new:
            results.append({"file": path_str, "status": "unmodified"})
            if not args.json:
                print(f"{green('[ OK ]')}  {green('Unmodified')}  {path_str}")
            unmodified_count += 1
        else:
            results.append({"file": path_str, "status": "modified"})
            if not args.json:
                print(f"{red('[FAIL]')}  {red('Modified (Hash mismatch!)')}  {path_str}")
            modified_count += 1

    total = len(baseline)
    summary = {
        "total": total,
        "unmodified": unmodified_count,
        "modified": modified_count,
        "missing": missing_count,
    }

    if args.json:
        output = {
            "timestamp": now,
            "algorithm": algorithm,
            "summary": summary,
            "results": results,
        }
        print(json.dumps(output, indent=2))
    else:
        color_status = green if modified_count == 0 and missing_count == 0 else red
        print(f"\n{cyan('--- Verification report')}  ({now}) {cyan('---')}")
        print(f"Total baseline entries : {bold(str(total))}")
        print(f"Unmodified            : {green(str(unmodified_count))}")
        print(f"Modified (tampered)   : {red(str(modified_count))}")
        print(f"Missing               : {yellow(str(missing_count))}")

    if modified_count or missing_count:
        sys.exit(2)


def cmd_update(args: argparse.Namespace) -> None:
    """Re-hash a subset of files and merge into the existing baseline."""
    baseline, metadata = load_baseline()
    if not baseline:
        print(f"{red('[FAIL]')}  No baseline found. Run 'init' first.", file=sys.stderr)
        sys.exit(1)

    algorithm = metadata.get("algorithm", "sha256")
    root = _resolve_path(args.path)
    if not root.exists():
        print(f"{red('[FAIL]')}  Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    fresh = _collect_hashes(root, algorithm=algorithm, exclude_patterns=args.exclude)

    for path_str, digest in fresh.items():
        baseline[path_str] = digest
        print(f"{cyan('[UPDATE]')}  {path_str}")

    save_baseline(baseline, metadata)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"{green('[ OK ]')}  Baseline updated — {cyan(str(len(fresh)))} entries refreshed  ({ts})")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="integrity_check",
        description="File Integrity Monitor — SHA-256 baseline auditing for log files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialise a new baseline")
    p_init.add_argument("path", help="File or directory to hash")
    p_init.add_argument(
        "--algorithm",
        default="sha256",
        choices=AVAILABLE_ALGORITHMS,
        help="Hash algorithm (default: sha256)",
    )
    p_init.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern of files to exclude (can be repeated)",
    )

    p_check = sub.add_parser("check", help="Verify files against the baseline")
    p_check.add_argument("path", help="File or directory to verify")
    p_check.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (for SIEM / pipeline ingestion)",
    )
    p_check.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern of files to exclude (can be repeated)",
    )

    p_update = sub.add_parser("update", help="Re-hash files and refresh the baseline")
    p_update.add_argument("path", help="File or directory to re-hash")
    p_update.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern of files to exclude (can be repeated)",
    )

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "update":
        cmd_update(args)


if __name__ == "__main__":
    main()
