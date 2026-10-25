import json

import pytest

from file_detector.cli import main
from file_detector.config import ScanConfig
from file_detector.models import FileReport, Finding, ScanReport
from file_detector.reports import render_html
from file_detector.scanner import Scanner
from file_detector.scoring import score_explanation, score_report
from file_detector.settings import Preferences, load_preferences, save_preferences


def test_score_breakdown_is_reconciled_and_exported():
    report = FileReport(
        "input",
        "input",
        findings=[
            Finding("a", "identity", "medium", "A", "", [], 20),
            Finding("a", "identity", "medium", "A duplicate", "", [], 20),
            Finding("b", "identity", "medium", "B", "", [], 20),
            Finding("c", "imports", "medium", "C", "", [], 80),
            Finding("d", "structure", "medium", "D", "", [], 35),
            Finding("e", "yara", "high", "E", "", [], 30),
            Finding("f", "test", "info", "F", "", [], 0),
        ],
    )
    score_report(report)
    breakdown = report.score_breakdown
    identity = next(c for c in breakdown["categories"] if c["category"] == "identity")
    assert identity["raw_points"] == 40
    assert identity["contribution"] == 30
    assert breakdown["subtotal"] == 130
    assert breakdown["global_reduction"] == 30
    assert breakdown["total"] == report.score == 100
    assert breakdown["duplicate_codes_ignored"] == ["a"]
    batch = ScanReport("target", files=[report])
    assert "Calcul du score" in render_html(batch)
    assert "40 points bruts" in render_html(batch)
    assert batch.to_dict()["files"][0]["score_breakdown"]["total"] == 100
    assert "score final : 100/100" in " ".join(score_explanation(report))


def test_preferences_roundtrip_and_invalid_file(tmp_path):
    path = tmp_path / "config" / "settings.json"
    assert load_preferences(path) == Preferences()
    wanted = Preferences(
        ScanConfig(
            max_files=7,
            recursive=False,
            analysis_timeout=2.5,
            memory_mb=256,
            exclude_patterns=("*.tmp", "build"),
        ),
        "/rules",
    )
    save_preferences(path, wanted)
    assert load_preferences(path) == wanted
    assert len(list(path.parent.iterdir())) == 1
    path.write_text('{"schema_version": 99}')
    with pytest.raises(ValueError):
        load_preferences(path)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"memory_mb": 63},
        {"analysis_timeout": 0},
        {"analysis_timeout": float("nan")},
        {"analysis_timeout": float("inf")},
        {"exclude_patterns": "*.tmp"},
        {"recursive": "yes"},
        {"max_files": True},
    ],
)
def test_invalid_settings(kwargs):
    with pytest.raises(ValueError):
        ScanConfig(**kwargs)


def test_exclusions_prune_folders_and_match_names(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "nested.txt").write_text("ignored")
    (tmp_path / "cache.tmp").write_text("ignored")
    (tmp_path / "keep.txt").write_text("keep")
    batch = Scanner(ScanConfig(exclude_patterns=("build", "*.tmp"))).scan(tmp_path)
    assert [f.name for f in batch.files] == ["keep.txt"]
    assert batch.excluded_entries == 2


def test_cli_new_options_and_explanation(tmp_path, capsys):
    path = tmp_path / "hello.txt"
    path.write_text("powershell DownloadString Invoke-Expression")
    output = tmp_path / "report.json"
    assert (
        main(
            [
                str(path),
                "--json",
                str(output),
                "--timeout",
                "3",
                "--memory-mb",
                "256",
                "--exclude",
                "*.tmp",
                "--explain",
                "--quiet",
            ]
        )
        == 0
    )
    report = json.loads(output.read_text())
    assert report["config"]["analysis_timeout"] == 3
    assert report["config"]["memory_mb"] == 256
    assert "*.tmp" in report["config"]["exclude_patterns"]
    assert "20 points bruts" in capsys.readouterr().out
    for args in (["--memory-mb", "1"], ["--timeout", "nan"]):
        with pytest.raises(SystemExit) as exc:
            main([str(path), *args])
        assert exc.value.code == 2
