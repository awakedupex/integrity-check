#!/usr/bin/env python3
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
# Hashing engine
# ---------------------------------------------------------------------------

def sha256_file(path: pathlib.Path) -> str:
    """Compute SHA-256 hex digest of *path* using a streaming 4 KB buffer.

    Chunking at 4096 bytes is a deliberate memory-safety choice: a 16 GB log
    file is never fully loaded into RAM.  Only the rolling digest state (32
    bytes for SHA-256) is held between reads, making the routine safe for
    production systems with limited memory.
    """
    h = hashlib.sha256()
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

def load_baseline() -> dict:
    """Deserialise the JSON baseline store; return empty dict on absence/corruption."""
    p = pathlib.Path(BASELINE_FILE)
    if not p.exists():
        return {}
    try:
        raw = p.read_text(encoding="utf-8")
        return dict(json.loads(raw))
    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] Baseline file corrupt or unreadable ({e}); starting fresh.")
        return {}


def save_baseline(baseline: dict) -> None:
    """Atomically write the baseline dict to *BASELINE_FILE*."""
    tmp = pathlib.Path(BASELINE_FILE + ".tmp")
    tmp.write_text(
        json.dumps(baseline, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    tmp.replace(BASELINE_FILE)


# ---------------------------------------------------------------------------
# File discovery helpers
# ---------------------------------------------------------------------------

def _resolve_path(raw: str) -> pathlib.Path:
    """Resolve user-supplied path, expanding ~ and symlinks."""
    return pathlib.Path(raw).expanduser().resolve()


def _iter_log_files(root: pathlib.Path):
    """Recursively yield regular files under *root* (or *root* itself if it is a file).

    Symlinks are intentionally skipped — following them could escape the
    intended audit boundary and create double-counting or TOCTOU issues.
    Also silently skips the baseline store itself to avoid self-referencing.
    """
    if root.is_file():
        yield root
        return

    for entry in root.rglob("*"):
        # Skip the baseline file if it happens to sit inside the scanned tree
        if entry.name == BASELINE_FILE:
            continue
        try:
            st = entry.lstat()
        except OSError:
            continue
        # Only regular files (not symlinks, sockets, fifos, etc.)
        if stat.S_ISREG(st.st_mode):
            yield entry


def _collect_hashes(root: pathlib.Path) -> dict:
    """Walk *root* and return ``{str(path): str(sha256)}``.

    Permission-denied files are reported to stderr and skipped.
    """
    result: dict[str, str] = {}
    for fp in _iter_log_files(root):
        try:
            digest = sha256_file(fp)
            result[str(fp)] = digest
        except PermissionError:
            print(f"[SKIP]  Permission denied: {fp}", file=sys.stderr)
        except OSError as e:
            print(f"[SKIP]  {e}", file=sys.stderr)
    return result


# ---------------------------------------------------------------------------
# CLI actions
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    """Initialise a new baseline by hashing every file under *path*."""
    root = _resolve_path(args.path)
    if not root.exists():
        print(f"[FAIL]  Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    baseline = _collect_hashes(root)
    if not baseline:
        print("[WARN]  No files found — baseline will be empty.", file=sys.stderr)

    save_baseline(baseline)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"[ OK ]  Baseline initialised: {len(baseline)} files hashed  ({ts})")


def cmd_check(args: argparse.Namespace) -> None:
    """Compare current file hashes against the stored baseline.

    Each file is classified as *Unmodified*, *Modified*, or *Missing*.
    """
    baseline = load_baseline()
    if not baseline:
        print("[FAIL]  No baseline found. Run 'init' first.", file=sys.stderr)
        sys.exit(1)

    root = _resolve_path(args.path)
    if not root.exists():
        print(f"[FAIL]  Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    modified_count = 0
    missing_count = 0
    unmodified_count = 0

    current = _collect_hashes(root)

    # Compare every path that was in the baseline and still exists
    all_paths = set(baseline.keys()) | set(current.keys())
    for path_str in sorted(all_paths):
        if path_str in baseline and path_str not in current:
            print(f"[MISS]  {path_str}")
            missing_count += 1
            continue
        if path_str not in baseline:
            # New file since init — not an error, but informational
            continue

        old = baseline[path_str]
        new = current[path_str]
        if old == new:
            print(f"[ OK ]  Unmodified  {path_str}")
            unmodified_count += 1
        else:
            print(f"[FAIL]  Modified (Hash mismatch!)  {path_str}")
            modified_count += 1

    total = len(baseline)
    print(f"\n--- Verification report  ({now}) ---")
    print(f"Total baseline entries : {total}")
    print(f"Unmodified            : {unmodified_count}")
    print(f"Modified (tampered)   : {modified_count}")
    print(f"Missing               : {missing_count}")

    if modified_count or missing_count:
        sys.exit(2)


def cmd_update(args: argparse.Namespace) -> None:
    """Re-hash a subset of files and merge into the existing baseline."""
    baseline = load_baseline()
    root = _resolve_path(args.path)
    if not root.exists():
        print(f"[FAIL]  Path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    fresh = _collect_hashes(root)

    # Recompute for the requested paths
    for path_str, digest in fresh.items():
        old = baseline.get(path_str, "<new>")
        baseline[path_str] = digest
        print(f"[UPDATE]  {path_str}")

    save_baseline(baseline)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"[ OK ]  Baseline updated — {len(fresh)} entries refreshed  ({ts})")


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

    p_check = sub.add_parser("check", help="Verify files against the baseline")
    p_check.add_argument("path", help="File or directory to verify")

    p_update = sub.add_parser("update", help="Re-hash files and refresh the baseline")
    p_update.add_argument("path", help="File or directory to re-hash")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "update":
        cmd_update(args)


if __name__ == "__main__":
    main()
