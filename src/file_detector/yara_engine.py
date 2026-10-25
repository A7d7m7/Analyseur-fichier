import hashlib
import json
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from .models import FileReport, Finding


@dataclass
class RuleSet:
    sources: dict[str, str] = field(default_factory=dict)
    digest: str | None = None
    error: str | None = None

    @classmethod
    def load(cls, rules_dir: Path | None = None):
        """Snapshot borné des règles ; aucune compilation dans le processus parent."""
        result = cls()
        try:
            root = rules_dir if rules_dir is not None else files("file_detector").joinpath("rules")
            paths = sorted(
                (p for p in root.iterdir() if p.name.endswith((".yar", ".yara"))),
                key=lambda p: p.name,
            )
            if not paths or len(paths) > 128:
                raise ValueError("le dossier doit contenir entre 1 et 128 règles .yar/.yara")
            remaining = 8 * 1024 * 1024
            for index, path in enumerate(paths):
                # Les règles personnalisées sont une configuration de confiance.
                if isinstance(path, Path) and (path.is_symlink() or not path.is_file()):
                    raise ValueError(f"règle non régulière : {path.name}")
                with path.open("rb") as handle:
                    data = handle.read(remaining + 1)
                remaining -= len(data)
                if remaining < 0:
                    raise ValueError("jeu de règles supérieur à 8 Mio")
                result.sources[f"rules_{index}"] = data.decode("utf-8")
            result.digest = hashlib.sha256(
                json.dumps(result.sources, sort_keys=True).encode()
            ).hexdigest()
        except (OSError, ValueError) as exc:
            result.error = f"YARA indisponible : {type(exc).__name__}: {exc}"
        return result


class YaraEngine:
    def __init__(
        self, rules_dir: Path | None = None, timeout: int = 5, ruleset: RuleSet | None = None
    ):
        self.timeout = timeout
        self.rules = None
        self.error = None
        snapshot = ruleset if ruleset is not None else RuleSet.load(rules_dir)
        self.digest = snapshot.digest
        if snapshot.error:
            self.error = snapshot.error
            return
        try:
            import yara

            self.rules = yara.compile(sources=snapshot.sources, includes=False)
        except MemoryError:
            raise
        except Exception as exc:  # noqa: BLE001 -- rendre toute erreur de compilation visible
            self.error = f"YARA indisponible : {type(exc).__name__}: {exc}"

    def analyze(self, report: FileReport, data: bytes) -> None:
        if self.error:
            report.status = "partial" if report.status == "complete" else report.status
            report.checks["yara"] = "unavailable"
            report.issues.append(self.error)
            return
        try:
            for match in self.rules.match(data=data, timeout=self.timeout):
                is_test = "test" in match.tags
                severity = str(match.meta.get("severity", "low"))
                points = 0 if is_test else {"low": 10, "medium": 20, "high": 30}.get(severity, 10)
                evidence = [f"Règle : {match.namespace}:{match.rule}"]
                for string in match.strings[:8]:
                    evidence.extend(
                        f"{string.identifier} à l'offset {instance.offset}"
                        for instance in string.instances[:3]
                    )
                report.findings.append(
                    Finding(
                        f"yara:{match.namespace}:{match.rule}",
                        "test" if is_test else "yara",
                        "info" if is_test else severity,
                        str(match.meta.get("description", match.rule)),
                        "Correspondance de motifs ; elle ne démontre pas une exécution ni un comportement malveillant.",
                        evidence,
                        points,
                    )
                )
            report.checks["yara"] = "complete"
        except MemoryError:
            raise
        except Exception as exc:  # noqa: BLE001 -- rendre toute erreur du moteur natif visible
            report.status = "partial" if report.status == "complete" else report.status
            report.checks["yara"] = "error"
            report.issues.append(f"Analyse YARA interrompue : {type(exc).__name__}: {exc}")
