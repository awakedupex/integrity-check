"""Pytest suite for integrity_check.py — File Integrity Monitor.

Run with:
    python -m pytest test_integrity.py -v

All tests use temporary directories and are self-contained.
"""

import json
import pathlib
import stat
import subprocess
import sys
import time

import pytest

CLI = pathlib.Path(__file__).with_name("integrity_check.py")
BASELINE = ".metadata_store.json"


def run(*args: str, cwd: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )


def baseline_path(cwd: pathlib.Path) -> pathlib.Path:
    return cwd / BASELINE


def assert_baseline_exists(cwd: pathlib.Path) -> dict:
    bp = baseline_path(cwd)
    assert bp.exists(), f"Baseline file {bp} not created"
    data = json.loads(bp.read_text(encoding="utf-8"))
    data.pop("_metadata", None)
    return data


def assert_baseline_metadata(cwd: pathlib.Path) -> dict:
    bp = baseline_path(cwd)
    data = json.loads(bp.read_text(encoding="utf-8"))
    return data.get("_metadata", {})


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_on_directory_creates_baseline(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "app.log").write_text("INFO: startup\n")
        (tmp_path / "auth.log").write_text("AUTH: login\n")

        result = run("init", str(tmp_path), cwd=tmp_path)

        assert result.returncode == 0
        baseline = assert_baseline_exists(tmp_path)
        for key in baseline:
            p = pathlib.Path(key)
            assert p.exists()

    def test_init_on_single_file(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "syslog"
        f.write_text("single line\n")

        result = run("init", str(f), cwd=tmp_path)

        assert result.returncode == 0
        baseline = assert_baseline_exists(tmp_path)
        assert len(baseline) == 1

    def test_init_empty_directory(self, tmp_path: pathlib.Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()

        result = run("init", str(d), cwd=tmp_path)

        assert result.returncode == 0
        baseline = assert_baseline_exists(tmp_path)
        assert len(baseline) == 0

    def test_init_nonexistent_path_fails(self, tmp_path: pathlib.Path) -> None:
        result = run("init", str(tmp_path / "nope"), cwd=tmp_path)
        assert result.returncode == 1

    def test_init_stores_metadata(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "test.log").write_text("data\n")

        run("init", str(tmp_path), cwd=tmp_path)

        metadata = assert_baseline_metadata(tmp_path)
        assert "algorithm" in metadata
        assert "created" in metadata
        assert metadata["algorithm"] == "sha256"

    def test_init_with_custom_algorithm(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "test.log").write_text("data\n")

        result = run("init", "--algorithm", "sha512", str(tmp_path), cwd=tmp_path)

        assert result.returncode == 0
        metadata = assert_baseline_metadata(tmp_path)
        assert metadata["algorithm"] == "sha512"

    def test_init_with_exclude_pattern(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "keep.log").write_text("keep\n")
        (tmp_path / "skip.tmp").write_text("skip\n")

        result = run("init", "--exclude", "*.tmp", str(tmp_path), cwd=tmp_path)

        assert result.returncode == 0
        baseline = assert_baseline_exists(tmp_path)
        assert len(baseline) == 1
        assert "skip.tmp" not in str(list(baseline.keys())[0])


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

class TestCheck:
    def test_check_unmodified(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "secure.log"
        f.write_text("line1\nline2\n")
        run("init", str(tmp_path), cwd=tmp_path)

        result = run("check", str(tmp_path), cwd=tmp_path)

        assert result.returncode == 0
        assert "Unmodified" in result.stdout

    def test_tamper_detection_midfile_insertion(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "messages.log"
        original_content = "Jan 01 12:00:00 host sshd[1234]: Accepted publickey\n" * 100
        f.write_text(original_content)

        run("init", str(tmp_path), cwd=tmp_path)

        content = f.read_text(encoding="utf-8")
        pos = min(500, len(content) - 1)
        tampered = content[:pos] + "X" + content[pos + 1:]
        f.write_text(tampered, encoding="utf-8")

        result = run("check", str(tmp_path), cwd=tmp_path)

        assert "Modified (Hash mismatch!)" in result.stdout, (
            f"Tamper not detected.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert result.returncode == 2, (
            f"Expected exit code 2 for tampered files, got {result.returncode}"
        )

    def test_tamper_detection_append(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "dmesg"
        f.write_text("original content\n")

        run("init", str(tmp_path), cwd=tmp_path)

        f.write_text("original content\nappended line\n")

        result = run("check", str(tmp_path), cwd=tmp_path)

        assert "Modified (Hash mismatch!)" in result.stdout
        assert result.returncode == 2

    def test_check_missing_file(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "deleted.log"
        f.write_text("delete me\n")
        run("init", str(tmp_path), cwd=tmp_path)

        f.unlink()

        result = run("check", str(tmp_path), cwd=tmp_path)

        assert "[MISS]" in result.stdout
        assert result.returncode == 2

    def test_check_no_baseline(self, tmp_path: pathlib.Path) -> None:
        result = run("check", str(tmp_path), cwd=tmp_path)
        assert result.returncode == 1
        assert "No baseline found" in result.stderr

    def test_check_json_output(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "test.log").write_text("hello\n")
        run("init", str(tmp_path), cwd=tmp_path)

        result = run("check", "--json", str(tmp_path), cwd=tmp_path)

        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert "timestamp" in output
        assert "summary" in output
        assert "results" in output
        assert output["summary"]["unmodified"] == 1
        assert output["results"][0]["status"] == "unmodified"

    def test_check_json_output_with_tamper(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "test.log"
        f.write_text("original\n")
        run("init", str(tmp_path), cwd=tmp_path)

        f.write_text("tampered\n")

        result = run("check", "--json", str(tmp_path), cwd=tmp_path)

        # Still valid JSON even on failure
        output = json.loads(result.stdout)
        assert output["summary"]["modified"] == 1
        assert output["results"][0]["status"] == "modified"
        assert result.returncode == 2


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

class TestUpdate:
    def test_update_single_file_changes_hash(self, tmp_path: pathlib.Path) -> None:
        f1 = tmp_path / "a.log"
        f2 = tmp_path / "b.log"
        f1.write_text("aaa\n")
        f2.write_text("bbb\n")

        run("init", str(tmp_path), cwd=tmp_path)

        f1.write_text("aaa\nCHANGED\n")

        result = run("update", str(f1), cwd=tmp_path)

        assert result.returncode == 0
        baseline = assert_baseline_exists(tmp_path)

        check_result = run("check", str(tmp_path), cwd=tmp_path)
        assert "Unmodified" in check_result.stdout


# ---------------------------------------------------------------------------
# Permission error handling
# ---------------------------------------------------------------------------

class TestPermissions:
    def test_permission_denied_is_graceful(self, tmp_path: pathlib.Path) -> None:
        subdir = tmp_path / "restricted"
        subdir.mkdir()
        (subdir / "secret.log").write_text("classified\n")

        subdir.chmod(0o000)

        try:
            (tmp_path / "public.log").write_text("public\n")

            result = run("init", str(tmp_path), cwd=tmp_path)

            assert result.returncode == 0
            baseline = assert_baseline_exists(tmp_path)

            baseline_paths = list(baseline.keys())
            assert any("public.log" in p for p in baseline_paths)
        finally:
            subdir.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)


# ---------------------------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------------------------

class TestBenchmark:
    BUDGET_MS = 500

    def test_init_and_check_within_budget(self, tmp_path: pathlib.Path) -> None:
        files: list[pathlib.Path] = []
        for i in range(20):
            p = tmp_path / f"log_{i:03d}.log"
            p.write_text("".join(f"line {j}\n" for j in range(50)))
            files.append(p)

        start = time.perf_counter()
        result_init = run("init", str(tmp_path), cwd=tmp_path)
        t_init = time.perf_counter() - start
        assert result_init.returncode == 0

        start = time.perf_counter()
        result_check = run("check", str(tmp_path), cwd=tmp_path)
        t_check = time.perf_counter() - start

        total_ms = (t_init + t_check) * 1000
        print(
            f"\n[PERF]  init={t_init*1000:.1f} ms  check={t_check*1000:.1f} ms  "
            f"total={total_ms:.1f} ms  (budget={self.BUDGET_MS} ms)",
        )
        assert total_ms < self.BUDGET_MS, (
            f"Exceeded budget: {total_ms:.1f} ms > {self.BUDGET_MS} ms"
        )
