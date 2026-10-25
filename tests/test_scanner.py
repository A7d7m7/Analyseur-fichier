import hashlib
import os
from pathlib import Path

import pytest

from file_detector.models import FileReport, Finding
from file_detector.scanner import ScanConfig, Scanner
from file_detector.scoring import score_report


@pytest.fixture
def scanner():
    return Scanner()


def save(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_benign_text_hash_and_no_alert(tmp_path, scanner):
    data = "Bonjour, fichier de test bénin.\n".encode()
    report = scanner.scan_file(save(tmp_path, "bonjour.txt", data))
    assert report.status == "complete"
    assert report.score == 0
    assert report.sha256 == hashlib.sha256(data).hexdigest()
    assert report.checks["yara"] == "complete"


def test_marker_is_informational(tmp_path, scanner):
    report = scanner.scan_file(save(tmp_path, "test.txt", b"FILE_DETECTOR_TEST_MARKER"))
    assert len(report.findings) == 1
    assert report.findings[0].category == "test"
    assert report.score == 0


def test_yara_combination_and_negative_control(tmp_path, scanner):
    one = scanner.scan_file(save(tmp_path, "one.ps1", b"powershell DownloadString"))
    combined = scanner.scan_file(
        save(tmp_path, "all.ps1", b"powershell DownloadString Invoke-Expression")
    )
    assert one.score == 0
    assert combined.score == 20
    assert any(f.category == "yara" for f in combined.findings)


def test_disguised_pe(tmp_path, scanner, pe_bytes):
    report = scanner.scan_file(save(tmp_path, "photo.jpg", pe_bytes()))
    assert report.format == "PE"
    assert "format_mismatch" in {f.code for f in report.findings}


def test_double_extension_and_malformed_pe(tmp_path, scanner):
    report = scanner.scan_file(save(tmp_path, "facture.pdf.exe", b"MZbad"))
    assert "double_extension" in {f.code for f in report.findings}
    assert report.status == "partial"
    assert report.checks["pe"] == "error"
    assert report.sha256


def test_pe_imports_real_parser_and_single_import_not_flagged(tmp_path, scanner, pe_bytes):
    names = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
    report = scanner.scan_file(save(tmp_path, "combined.exe", pe_bytes(imports=names)))
    assert report.pe["architecture"] == "IMAGE_FILE_MACHINE_I386"
    assert set(report.pe["imports"][0]["symbols"]) == set(names)
    assert "remote_memory" in {f.code for f in report.findings}
    single = scanner.scan_file(
        save(tmp_path, "single.exe", pe_bytes(imports=("WriteProcessMemory",)))
    )
    assert not any(f.category == "imports" for f in single.findings)


def test_sections_entropy_permissions_and_packing(tmp_path, scanner, pe_bytes):
    data = pe_bytes(high_entropy=True, writable=True, section_name=b"UPX0")
    report = scanner.scan_file(save(tmp_path, "packed.exe", data))
    codes = {f.code for f in report.findings}
    assert {"high_entropy_0", "writable_executable_0", "packing_name_0"} <= codes
    assert report.pe["sections"][0]["entropy"] == 8.0
    assert report.score == 35


def test_score_caps_duplicates_and_status():
    report = FileReport(
        "x",
        "x",
        findings=[
            Finding("a", "identity", "medium", "a", "a", [], 20),
            Finding("a", "identity", "medium", "a", "a", [], 20),
            Finding("b", "identity", "medium", "b", "b", [], 20),
        ],
    )
    score_report(report)
    assert report.score == 30
    assert report.risk == "modéré"
    report.findings = []
    report.status = "partial"
    score_report(report)
    assert report.risk == "indéterminé"


def test_unsupported_not_clean(tmp_path, scanner):
    report = scanner.scan_file(save(tmp_path, "unknown.bin", b"\x00\x01\xfe"))
    assert report.status == "unsupported"
    assert report.risk == "indéterminé"


def test_zip_based_document_has_no_extension_mismatch(tmp_path, scanner):
    report = scanner.scan_file(save(tmp_path, "document.docx", b"PK\x03\x04demo"))
    assert not report.findings
    assert "non interprété" in report.checks["coverage"]


def test_size_limit_and_missing_file(tmp_path):
    scanner = Scanner(ScanConfig(max_bytes=4))
    report = scanner.scan_file(save(tmp_path, "big.txt", b"12345"))
    assert report.status == "skipped"
    assert report.sha256 is None
    assert scanner.scan_file(tmp_path / "absent").status == "error"


@pytest.mark.skipif(os.name == "nt", reason="Tests des fichiers spéciaux POSIX")
def test_links_fifo_and_directory_loop_not_followed(tmp_path, scanner):
    original = save(tmp_path, "original.txt", b"hello")
    link = tmp_path / "link.txt"
    link.symlink_to(original)
    (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    batch = scanner.scan(tmp_path)
    assert len(batch.files) == 4
    assert sum(f.status == "skipped" for f in batch.files) == 3


def test_batch_recursion_limit_and_cancel(tmp_path, scanner):
    save(tmp_path, "one.txt", b"one")
    (tmp_path / "sub").mkdir()
    save(tmp_path / "sub", "two.txt", b"two")
    (tmp_path / ".venv").mkdir()
    save(tmp_path / ".venv", "ignored.txt", b"ignored")
    assert len(scanner.scan(tmp_path).files) == 2
    assert len(Scanner(ScanConfig(recursive=False)).scan(tmp_path).files) == 1
    limited = Scanner(ScanConfig(max_files=1)).scan(tmp_path)
    assert limited.truncated and len(limited.files) == 1
    cancelled = scanner.scan(tmp_path, cancelled=lambda: True)
    assert cancelled.cancelled and not cancelled.files


def test_progress_and_output_exclusion(tmp_path, scanner):
    save(tmp_path, "one.txt", b"one")
    output = save(tmp_path, "report.json", b"{}")
    updates = []
    report = scanner.scan(tmp_path, progress=updates.append, exclude={output})
    assert len(updates) == len(report.files) == 1
    assert report.files[0].name == "one.txt"


def test_invalid_and_empty_yara_rules_are_reported(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    file = save(tmp_path, "normal.txt", b"normal")
    for source in (None, "rule invalid !!!"):
        if source:
            (rules / "bad.yar").write_text(source)
        report = Scanner(rules_dir=rules).scan_file(file)
        assert report.status == "partial"
        assert report.risk == "indéterminé"
        assert report.checks["yara"] == "unavailable"


def test_yara_failure_is_not_silent(tmp_path, scanner):
    from file_detector.analyzer import FileAnalyzer

    scanner = FileAnalyzer()

    class TimeoutRules:
        def match(self, **kwargs):
            raise TimeoutError("deadline")

    scanner.yara.rules = TimeoutRules()
    report = scanner.scan_file(save(tmp_path, "normal.txt", b"normal"))
    assert report.status == "partial"
    assert report.checks["yara"] == "error"


def test_permission_error_keeps_other_files(tmp_path, scanner, monkeypatch):
    from file_detector.analyzer import FileAnalyzer

    analyzer = FileAnalyzer()
    # Injection au niveau du lecteur : un patch Python ne traverse pas le processus isolé.
    monkeypatch.setattr(scanner, "scan_file", lambda path, cancelled=None: analyzer.scan_file(path))
    original = Path.lstat
    save(tmp_path, "blocked.txt", b"blocked")
    save(tmp_path, "ok.txt", b"ok")

    def patched(path):
        if path.name == "blocked.txt":
            raise PermissionError("denied")
        return original(path)

    monkeypatch.setattr(Path, "lstat", patched)
    report = scanner.scan(tmp_path)
    assert len(report.files) == 2
    assert report.files[0].status == "error"
    assert report.files[1].status == "complete"


def test_directory_walk_error_is_reported(tmp_path, scanner, monkeypatch):
    def failed_walk(target, followlinks, onerror):
        onerror(PermissionError("denied"))
        return iter(())

    monkeypatch.setattr(os, "walk", failed_walk)
    report = scanner.scan(tmp_path)
    assert report.issues


@pytest.mark.parametrize("kwargs", [{"max_bytes": 0}, {"max_files": -1}, {"yara_timeout": 0}])
def test_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        ScanConfig(**kwargs)
