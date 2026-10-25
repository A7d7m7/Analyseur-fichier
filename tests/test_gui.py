import os
import time

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DISPLAY"), reason="Nécessite un affichage (xvfb-run convient)"
)


def test_gui_scan_filter_detail_and_export(tmp_path, monkeypatch):
    import tkinter as tk
    from tkinter import filedialog

    from file_detector.gui import Application

    source = tmp_path / "bonjour.txt"
    source.write_text("Bonjour")
    root = tk.Tk()
    app = Application(root, settings_path=tmp_path / "settings.json")
    try:
        app.start(source)
        deadline = time.monotonic() + 10
        while app.running and time.monotonic() < deadline:
            root.update()
            time.sleep(0.02)
        assert not app.running
        assert app.report.files[0].score == 0
        assert len(app.table.get_children()) == 1
        app.table.selection_set("0")
        app.show_details()
        assert "SHA-256" in app.details.get("1.0", "end")
        app.filter.set("Avec indices")
        app.refresh()
        assert not app.table.get_children()
        monkeypatch.setattr(
            filedialog, "asksaveasfilename", lambda **kwargs: str(tmp_path / "export.html")
        )
        app.export("html")
        assert (tmp_path / "export.html").exists()
        root.update()
        assert app.footer.winfo_ismapped()
        assert (
            app.footer.winfo_rooty() + app.footer.winfo_height()
            <= root.winfo_rooty() + root.winfo_height()
        )
    finally:
        app.close()


def test_gui_settings_dialog_controls_the_scan(tmp_path):
    import tkinter as tk
    from tkinter import ttk

    from file_detector.gui import Application
    from file_detector.settings import load_preferences

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "all.yar").write_text("rule Always { condition: true }")
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "hello.txt").write_text("hello")
    (samples / "ignore.tmp").write_text("ignore")
    (samples / "sub").mkdir()
    (samples / "sub" / "nested.txt").write_text("nested")
    root = tk.Tk()
    app = Application(root, settings_path=tmp_path / "settings.json")
    try:
        app.open_settings()
        dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
        frame = dialog.winfo_children()[0]
        entries = {
            int(w.grid_info()["row"]): w for w in frame.winfo_children() if isinstance(w, ttk.Entry)
        }
        for row, value in [
            (0, "8"),
            (1, "2"),
            (2, "5"),
            (3, "256"),
            (7, "*.tmp"),
            (10, str(rules)),
        ]:
            entries[row].delete(0, "end")
            entries[row].insert(0, value)
        next(w for w in frame.winfo_children() if isinstance(w, ttk.Checkbutton)).invoke()
        next(
            w
            for w in frame.winfo_children()
            if isinstance(w, ttk.Button) and w.cget("text") == "Enregistrer"
        ).invoke()
        preferences = load_preferences(tmp_path / "settings.json")
        assert preferences == app.preferences
        assert preferences.scan.recursive is False
        assert preferences.scan.memory_mb == 256
        app.start(samples)
        deadline = time.monotonic() + 10
        while app.running and time.monotonic() < deadline:
            root.update()
            time.sleep(0.02)
        assert not app.running
        assert len(app.report.files) == 1
        assert app.report.files[0].score == 10
        assert app.report.config["max_bytes"] == 8 * 1024 * 1024
        assert app.report.excluded_entries == 1
        app.table.selection_set("0")
        app.show_details()
        assert "CALCUL DU SCORE" in app.details.get("1.0", "end")
    finally:
        app.close()


def test_gui_close_stops_active_process(tmp_path, monkeypatch):
    import sys
    import tkinter as tk

    import psutil

    from file_detector import isolation
    from file_detector.gui import Application

    pid_path = tmp_path / "pid"
    script = tmp_path / "slow_worker.py"
    script.write_text(
        f"import os,time\nfrom pathlib import Path\nPath({str(pid_path)!r}).write_text(str(os.getpid()))\ntime.sleep(60)\n"
    )
    monkeypatch.setattr(
        isolation, "worker_command", lambda request, result: [sys.executable, str(script)]
    )
    root = tk.Tk()
    app = Application(root, settings_path=tmp_path / "settings.json")
    app.start(tmp_path / "input.txt")
    deadline = time.monotonic() + 5
    while not pid_path.exists() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)
    try:
        assert pid_path.exists()
        app.close()
        deadline = time.monotonic() + 3
        while app.running and time.monotonic() < deadline:
            root.update()
            time.sleep(0.02)
        assert not app.running
        assert app.report.cancelled
        assert app.report.files[0].status == "cancelled"
        assert not psutil.pid_exists(int(pid_path.read_text()))
    finally:
        if app.running:
            app.close()
