import sys
import time
from pathlib import Path

import psutil
import pytest

from file_detector import isolation
from file_detector.config import ScanConfig
from file_detector.scanner import Scanner


def custom_worker(tmp_path, monkeypatch, body):
    script = tmp_path / "worker_fixture.py"
    script.write_text(body)
    monkeypatch.setattr(
        isolation,
        "worker_command",
        lambda request, result: [sys.executable, str(script), str(request), str(result)],
    )


def test_timeout_kills_worker_and_preserves_checkpoint(tmp_path, monkeypatch):
    pidfile = tmp_path / "pid"
    custom_worker(
        tmp_path,
        monkeypatch,
        f"""
import os, sys, time
from pathlib import Path
from file_detector.models import FileReport, Finding
from file_detector.worker import save_snapshot
report = FileReport("untrusted", "untrusted", findings=[Finding("test", "identity", "medium", "Indice", "Preuve", [], 20)])
save_snapshot(Path(sys.argv[2]), report, False)
Path({str(pidfile)!r}).write_text(str(os.getpid()))
time.sleep(60)
""",
    )
    source = tmp_path / "input.txt"
    source.write_text("hello")
    started = time.monotonic()
    report = Scanner(ScanConfig(analysis_timeout=0.6)).scan_file(source)
    assert time.monotonic() - started < 3
    assert report.status == "timeout"
    assert report.score == 20
    assert report.path == str(source)
    assert report.checks["yara"] == "not_completed"
    assert not psutil.pid_exists(int(pidfile.read_text()))


def test_cancellation_stops_current_file_and_remaining_batch(tmp_path, monkeypatch):
    ready = tmp_path / "ready"
    custom_worker(
        tmp_path,
        monkeypatch,
        f"""
import os, time
from pathlib import Path
Path({str(ready)!r}).write_text(str(os.getpid()))
time.sleep(60)
""",
    )
    folder = tmp_path / "samples"
    folder.mkdir()
    (folder / "first.txt").write_text("first")
    (folder / "second.txt").write_text("second")
    started = time.monotonic()
    batch = Scanner().scan(folder, cancelled=ready.exists)
    assert time.monotonic() - started < 3
    assert batch.cancelled
    assert len(batch.files) == 1
    assert batch.files[0].status == "cancelled"
    assert not psutil.pid_exists(int(ready.read_text()))


def test_worker_crash_does_not_stop_next_file(tmp_path, monkeypatch):
    custom_worker(
        tmp_path,
        monkeypatch,
        """
import json, os, sys
from pathlib import Path
from file_detector.worker import main
request = json.loads(Path(sys.argv[1]).read_text())
if Path(request["path"]).name == "bad.txt":
    os._exit(13)
raise SystemExit(main())
""",
    )
    folder = tmp_path / "samples"
    folder.mkdir()
    (folder / "bad.txt").write_text("bad")
    (folder / "good.txt").write_text("good")
    batch = Scanner().scan(folder)
    assert [f.status for f in batch.files] == ["error", "complete"]
    assert "13" in batch.files[0].issues[0]


def test_rss_budget_kills_excessive_process(tmp_path, monkeypatch):
    custom_worker(
        tmp_path,
        monkeypatch,
        """
import time
data = bytearray(128 * 1024 * 1024)
time.sleep(60)
""",
    )
    report = Scanner(ScanConfig(memory_mb=64)).scan_file(tmp_path / "irrelevant")
    assert report.status == "resource_limit"
    assert report.risk == "indéterminé"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Plafond RLIMIT_AS Linux")
def test_real_worker_memory_error_is_reported(tmp_path):
    path = tmp_path / "large.txt"
    with path.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)
    report = Scanner(ScanConfig(memory_mb=64)).scan_file(path)
    assert report.status == "resource_limit"
    assert "Allocation refusée" in " ".join(report.issues)
    assert report.checks["yara"] == "not_completed"


def test_keyboard_interrupt_reaps_child(tmp_path, monkeypatch):
    ready = tmp_path / "pid"
    custom_worker(
        tmp_path,
        monkeypatch,
        f"""
import os, time
from pathlib import Path
Path({str(ready)!r}).write_text(str(os.getpid()))
time.sleep(60)
""",
    )

    def interrupt():
        if ready.exists():
            raise KeyboardInterrupt
        return False

    with pytest.raises(KeyboardInterrupt):
        Scanner().scan_file(tmp_path / "input", cancelled=interrupt)
    assert not psutil.pid_exists(int(ready.read_text()))


def test_invalid_worker_result_is_not_clean(tmp_path, monkeypatch):
    custom_worker(
        tmp_path,
        monkeypatch,
        """
import sys
from pathlib import Path
Path(sys.argv[2]).write_text("not json")
""",
    )
    report = Scanner().scan_file(tmp_path / "input")
    assert report.status == "error"
    assert report.risk == "indéterminé"


def test_parent_does_not_import_native_parsers(tmp_path):
    # Contrôle dans un interpréteur neuf, indépendant des imports des autres tests.
    import subprocess

    path = tmp_path / "sample.txt"
    path.write_text("hello")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; from file_detector.scanner import Scanner; import sys; r=Scanner().scan_file(Path(sys.argv[1])); assert r.status=='complete'; assert 'pefile' not in sys.modules; assert 'yara' not in sys.modules",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_result_size_bound(tmp_path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (isolation.MAX_RESULT_BYTES + 1))
    with pytest.raises(ValueError, match="4 Mio"):
        isolation.read_result(path, Path("input"))


def test_rules_snapshot_stays_stable_during_scan(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    rule = rules / "custom.yar"
    rule.write_text("rule original { condition: true }")
    scanner = Scanner(rules_dir=rules)
    digest = scanner.ruleset.digest
    rule.write_text("invalid syntax")
    path = tmp_path / "hello.txt"
    path.write_text("hello")
    report = scanner.scan(path)
    assert report.files[0].checks["yara"] == "complete"
    assert report.config["rules_sha256"] == digest
