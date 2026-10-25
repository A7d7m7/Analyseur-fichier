"""Supervision sans parseur natif dans le parent ; échanges JSON bornés sur disque privé."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import psutil

from .models import FileReport, Finding
from .scoring import score_report

MAX_RESULT_BYTES = 4 * 1024 * 1024


def worker_command(request: Path, result: Path) -> list[str]:
    return [sys.executable, "-m", "file_detector.worker", str(request), str(result)]


def read_result(path: Path, source: Path) -> tuple[FileReport, bool]:
    # Pas de pickle ni de chemin de cible fourni par le processus analysant les données.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Le résultat du processus n'est pas un fichier régulier.")
        data = handle.read(MAX_RESULT_BYTES + 1)
    if len(data) > MAX_RESULT_BYTES:
        raise ValueError("Résultat supérieur à 4 Mio.")
    payload = json.loads(data)
    raw = payload["report"]
    raw["findings"] = [Finding(**f) for f in raw["findings"]]
    raw["path"], raw["name"] = str(source), source.name
    report = FileReport(**raw)
    score_report(report)
    return report, payload["done"] is True


def analyze_isolated(path, config, ruleset, cancelled=None):
    report = FileReport(str(path), path.name)
    reason = None
    process = None
    done = False
    with tempfile.TemporaryDirectory(prefix="file-detector-") as directory:
        request_path, result_path = (
            Path(directory) / "request.json",
            Path(directory) / "result.json",
        )
        request_path.write_text(
            json.dumps({"path": str(path), "config": asdict(config), "ruleset": asdict(ruleset)}),
            encoding="utf-8",
        )
        started = time.monotonic()
        try:
            if cancelled and cancelled():
                reason = ("cancelled", "Analyse annulée avant démarrage.")
            else:
                process = subprocess.Popen(
                    worker_command(request_path, result_path),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                monitored = psutil.Process(process.pid)
                while process.poll() is None:
                    if cancelled and cancelled():
                        reason = ("cancelled", "Analyse interrompue à la demande de l'utilisateur.")
                        break
                    if time.monotonic() - started >= config.analysis_timeout:
                        reason = (
                            "timeout",
                            f"Délai global de {config.analysis_timeout:g} s dépassé (démarrage, lecture et parseurs compris).",
                        )
                        break
                    try:
                        if monitored.memory_info().rss > config.memory_mb * 1024 * 1024:
                            reason = (
                                "resource_limit",
                                f"Budget mémoire de {config.memory_mb} Mio dépassé.",
                            )
                            break
                    except psutil.NoSuchProcess:
                        break
                    time.sleep(0.05)
        except (OSError, psutil.Error) as exc:
            reason = ("error", f"Supervision impossible : {exc}")
        finally:
            # Aussi exécuté sur Ctrl+C : ne jamais abandonner un analyseur actif.
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
        if result_path.exists():
            try:
                report, done = read_result(result_path, path)
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
                reason = reason or ("error", f"Résultat du processus invalide : {exc}")
        if reason is None and (not done or process is None or process.returncode != 0):
            code = process.returncode if process else "non démarré"
            reason = (
                "error",
                f"Le processus d'analyse s'est arrêté sans résultat complet (code {code}).",
            )
        if reason:
            report.status, message = reason
            report.issues.append(message)
            report.checks["isolation"] = report.status
        else:
            report.checks["isolation"] = "complete"
        if report.status in {"error", "timeout", "resource_limit", "cancelled"}:
            for check in ("identity", "sha256", "pe", "yara"):
                report.checks.setdefault(check, "not_completed")
        score_report(report)
        return report
