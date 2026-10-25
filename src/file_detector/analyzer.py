"""Analyse un fichier dans le processus enfant ; ne pas utiliser depuis l'interface."""

import hashlib
import os
import stat
from pathlib import Path

from .config import ScanConfig
from .identity import PE_EXTENSIONS, analyze_identity
from .models import FileReport
from .pe import analyze_pe
from .scoring import score_report
from .yara_engine import RuleSet, YaraEngine


class FileAnalyzer:
    def __init__(self, config: ScanConfig | None = None, ruleset: RuleSet | None = None):
        self.config = config or ScanConfig()
        self.yara = YaraEngine(timeout=self.config.yara_timeout, ruleset=ruleset)

    def scan_file(self, path: Path, checkpoint=None) -> FileReport:
        path = Path(path).absolute()
        report = FileReport(path=str(path), name=path.name)
        try:
            info = path.lstat()
            report.size = info.st_size
            if not stat.S_ISREG(info.st_mode):
                report.status = "skipped"
                report.issues.append("Liens symboliques et fichiers spéciaux ignorés.")
                return report
            if info.st_size > self.config.max_bytes:
                report.status = "skipped"
                report.issues.append(
                    f"Taille supérieure à la limite de {self.config.max_bytes} octets."
                )
                return report
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(path, flags), "rb") as handle:
                before = os.fstat(handle.fileno())
                if not stat.S_ISREG(before.st_mode) or (info.st_dev, info.st_ino) != (
                    before.st_dev,
                    before.st_ino,
                ):
                    raise OSError("Le fichier a changé pendant son ouverture.")
                data = handle.read(self.config.max_bytes + 1)
                after = os.fstat(handle.fileno())
            if len(data) > self.config.max_bytes:
                report.status = "skipped"
                report.issues.append("Le fichier dépasse la limite de taille pendant la lecture.")
                return report
            report.size = len(data)
            report.sha256 = hashlib.sha256(data).hexdigest()
            report.checks["sha256"] = "complete"
            analyze_identity(report, data)
            if checkpoint:
                checkpoint(report)
            if report.format == "MZ" or report.extension in PE_EXTENSIONS:
                analyze_pe(report, data)
            else:
                report.checks["pe"] = "not_applicable"
            if checkpoint:
                checkpoint(report)
            self.yara.analyze(report, data)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                report.status = "partial"
                report.issues.append(
                    "Fichier modifié pendant la lecture ; SHA-256 et analyses portent sur les octets lus."
                )
        except OSError as exc:
            report.status = "error"
            report.issues.append(f"Lecture impossible : {exc}")
        finally:
            score_report(report)
        return report
