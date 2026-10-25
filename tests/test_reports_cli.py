import json

import pytest

from file_detector.cli import main
from file_detector.models import FileReport, ScanReport
from file_detector.reports import render_html, write_report


def test_html_escapes_untrusted_names_and_evidence(tmp_path):
    report = ScanReport(
        "<script>alert(1)</script>",
        files=[
            FileReport(
                str(tmp_path / "input"),
                '<img src=x onerror="alert(1)">',
                issues=["<svg onload=alert(1)>"],
            )
        ],
    )
    html = render_html(report)
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;img" in html
    assert "Content-Security-Policy" in html


def test_json_roundtrip_and_no_overwrite(tmp_path):
    report = ScanReport(str(tmp_path / "source"))
    output = tmp_path / "out" / "report.json"
    write_report(report, output, "json")
    assert json.loads(output.read_text())["schema_version"] == "1.1"
    with pytest.raises(FileExistsError):
        write_report(report, output, "json")
    write_report(report, output, "json", overwrite=True)
    assert len(list(output.parent.iterdir())) == 1


def test_input_cannot_be_overwritten_even_with_force(tmp_path):
    source = tmp_path / "input.txt"
    source.write_text("original")
    report = ScanReport(str(tmp_path), files=[FileReport(str(source), source.name)])
    with pytest.raises(ValueError):
        write_report(report, source, "json", overwrite=True)
    assert source.read_text() == "original"


def test_cli_end_to_end_reports_and_output_exclusion(tmp_path):
    source = tmp_path / "hello.txt"
    source.write_text("hello")
    json_path, html_path = tmp_path / "report.json", tmp_path / "report.html"
    argv = [str(tmp_path), "--json", str(json_path), "--html", str(html_path), "--quiet"]
    assert main(argv) == 0
    assert json.loads(json_path.read_text())["summary"]["total"] == 1
    assert "hello.txt" in html_path.read_text()
    assert main(argv + ["--force"]) == 0
    assert json.loads(json_path.read_text())["summary"]["total"] == 1


def test_cli_exit_codes_and_conflicting_outputs(tmp_path):
    assert main([str(tmp_path / "missing"), "--quiet"]) == 2
    source = tmp_path / "test.txt"
    source.write_text(
        "powershell -EncodedCommand -WindowStyle Hidden DownloadString Invoke-Expression"
    )
    assert main([str(source), "--quiet"]) == 1
    with pytest.raises(SystemExit) as error:
        main([str(source), "--json", str(source), "--force"])
    assert error.value.code == 2
    with pytest.raises(SystemExit):
        main([str(source), "--json", str(tmp_path / "report"), "--html", str(tmp_path / "report")])
