"""Point d'entrée interne d'un processus d'analyse jetable, jamais la cible analysée."""

import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .config import ScanConfig
from .models import FileReport
from .scoring import score_report

MAX_RESULT_BYTES = 4 * 1024 * 1024


def apply_memory_limit(memory_mb: int) -> str:
    # Linux : plafond d'espace virtuel dur, en plus du contrôle RSS par le parent.
    if sys.platform.startswith("linux"):
        import resource

        limit = memory_mb * 1024 * 1024
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        if hard != resource.RLIM_INFINITY:
            limit = min(limit, hard)
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return f"Linux : RLIMIT_AS dur de {limit // (1024 * 1024)} Mio + surveillance RSS toutes les 50 ms"
    return "Surveillance RSS toutes les 50 ms ; pas de plafond d'espace virtuel dur sur ce système"


def save_snapshot(destination: Path, report: FileReport, done: bool):
    score_report(report)
    content = json.dumps({"done": done, "report": asdict(report)}, ensure_ascii=True).encode()
    if len(content) > MAX_RESULT_BYTES:
        report.pe = None
        report.status = "partial"
        report.issues.append("Détails PE omis : le résultat dépassait 4 Mio.")
        content = json.dumps({"done": done, "report": asdict(report)}, ensure_ascii=True).encode()
        if len(content) > MAX_RESULT_BYTES:
            raise ValueError("Résultat encore supérieur à 4 Mio après réduction.")
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(content)
    os.replace(temporary, destination)


def main():
    request = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    destination = Path(sys.argv[2])
    config = ScanConfig(**request["config"])
    source = Path(request["path"])
    report = FileReport(str(source), source.name)
    reserve = None
    try:
        policy = apply_memory_limit(config.memory_mb)
        reserve = bytearray(1024 * 1024)
        from .analyzer import FileAnalyzer
        from .yara_engine import RuleSet

        def checkpoint(current):
            nonlocal report
            report = current
            report.checks["memory_policy"] = policy
            save_snapshot(destination, report, False)

        report.checks["memory_policy"] = policy
        save_snapshot(destination, report, False)
        analyzer = FileAnalyzer(config, RuleSet(**request["ruleset"]))
        report = analyzer.scan_file(source, checkpoint=checkpoint)
        report.checks["memory_policy"] = policy
    except MemoryError:
        reserve = None
        report.status = "resource_limit"
        report.issues.append(
            f"Allocation refusée dans le budget mémoire de {config.memory_mb} Mio."
        )
    except Exception as exc:  # noqa: BLE001 -- frontière du processus, erreur conservée
        report.status = "error"
        report.issues.append(f"Échec du processus : {type(exc).__name__}: {exc}")
    finally:
        del reserve
    save_snapshot(destination, report, True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
