# Integrity Check — File Integrity Monitoring CLI

SHA-256 baseline auditing for log files. Detects unauthorized tampering or manual modifications using cryptographic hash comparison.

## Quickstart

```bash
# No pip install required — uses only Python standard library.

# Initialise a baseline
python3 integrity_check.py init /var/log

# Verify files against baseline
python3 integrity_check.py check /var/log

# Re-hash after log rotation
python3 integrity_check.py update /var/log/auth.log
```

## Commands

| Command | Description |
|---|---|
| `init <path>` | Recursively hash all files, save baseline to `.metadata_store.json` |
| `check <path>` | Recompute hashes and compare — reports `Unmodified` / `Modified (Hash mismatch!)` / `Missing` |
| `update <path>` | Re-hash a subset of files and merge into the existing baseline |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All files unmodified (or init/update succeeded) |
| `1` | CLI error (no baseline, bad path) |
| `2` | Integrity violation detected (tamper or missing files) |

## Why SHA-256?

- **FIPS 140-2 compliant** — required by CIS Benchmarks, STIGs, and FedRAMP auditing guidelines.
- **Collision-resistant** — no practical collision attack exists (unlike MD5/SHA-1).
- **Standard library** — `hashlib` ships with every Python install. No dependencies.

## Why 4096-byte chunks?

A 16 GB log file is never fully loaded into RAM. Only the rolling SHA-256 digest state (32 bytes) is held between reads. This makes the tool safe for production systems with limited memory, without sacrificing I/O throughput.

## Design Decisions

- **JSON baseline** — zero dependencies, human-readable, trivially diff-able in code review.
- **Atomic writes** — baseline is written to `.metadata_store.json.tmp` then atomically renamed, preventing corruption on interrupted writes.
- **Permission safety** — `PermissionError` is caught per-file; the tool reports the skip on stderr and continues.
- **Symlink protection** — symlinks are skipped to prevent escape from the audit boundary.

## Development

```bash
make install    # install pytest
make test       # run 12-test suite
make clean      # remove cache and baseline files
```

### Test Coverage

| Test | What it validates |
|---|---|
| `test_init_*` | Baseline creation on files, directories, empty dirs, missing paths |
| `test_check_unmodified` | Unchanged files report `Unmodified` |
| `test_tamper_detection_midfile_insertion` | Mid-file byte change → mismatch (0% false-negative) |
| `test_tamper_detection_append` | Content append → mismatch |
| `test_check_missing_file` | File deleted after init → `[MISS]` |
| `test_permission_denied_is_graceful` | `chmod 000` directory doesn't crash |
| `test_init_and_check_within_budget` | 20 files init+check under 500 ms |

## Project Structure

```
integrity_check.py    # CLI tool (256 lines)
test_integrity.py     # Pytest suite (264 lines)
Makefile              # Build automation
.gitignore            # Ignore artifacts
requirements-dev.txt  # Dev dependencies (pytest only)
```

## Future Enhancements

- **Baseline signing** — sign `.metadata_store.json` with an RSA key to prevent undetected baseline tampering.
- **Concurrent hashing** — `ThreadPoolExecutor` for parallel file processing on large directories.
- **Daemon mode** — continuous monitoring with inotify / kqueue instead of on-demand checks.
- **SIEM output** — `--json` flag emitting structured events for Splunk / ELK ingestion.
- **Configuration file** — customizable algorithms, exclusions, and baseline paths.
