import fnmatch
import os
from collections.abc import Callable, Iterator
from dataclasses import asdict
from pathlib import Path

from .config import ScanConfig
from .isolation import analyze_isolated
from .models import FileReport, ScanReport, timestamp
from .yara_engine import RuleSet


class Scanner:
    def __init__(self, config: ScanConfig | None = None, rules_dir: Path | None = None):
        self.config = config or ScanConfig()
        self.ruleset = RuleSet.load(rules_dir)

    def scan_file(self, path: Path, cancelled: Callable[[], bool] | None = None) -> FileReport:
        return analyze_isolated(Path(path).absolute(), self.config, self.ruleset, cancelled)

    def _excluded(self, path: Path, target: Path) -> bool:
        relative = path.relative_to(target).as_posix() if path != target else path.name
        return any(
            fnmatch.fnmatchcase(path.name, pattern) or fnmatch.fnmatchcase(relative, pattern)
            for pattern in self.config.exclude_patterns
        )

    def _paths(self, target: Path, batch: ScanReport, cancelled) -> Iterator[Path]:
        if self._excluded(target, target):
            batch.excluded_entries += 1
            return
        if target.is_symlink() or not target.is_dir():
            yield target
            return

        def onerror(exc: OSError) -> None:
            batch.issues.append(f"Dossier inaccessible : {exc}")

        for root, dirs, names in os.walk(target, followlinks=False, onerror=onerror):
            if cancelled and cancelled():
                batch.cancelled = True
                return
            for name in sorted(dirs):
                path = Path(root) / name
                if self._excluded(path, target):
                    dirs.remove(name)
                    batch.excluded_entries += 1
                elif path.is_symlink():
                    dirs.remove(name)
                    yield path
            dirs.sort()
            for name in sorted(names):
                path = Path(root) / name
                if self._excluded(path, target):
                    batch.excluded_entries += 1
                else:
                    yield path
            if not self.config.recursive:
                dirs.clear()

    def scan(
        self,
        target: Path,
        progress: Callable[[FileReport], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
        exclude: set[Path] | None = None,
    ) -> ScanReport:
        target = Path(target).absolute()
        batch = ScanReport(
            target=str(target), config={**asdict(self.config), "rules_sha256": self.ruleset.digest}
        )
        if self.ruleset.error:
            batch.issues.append(self.ruleset.error)
        excluded = {p.resolve() for p in (exclude or set())}
        for path in self._paths(target, batch, cancelled):
            if cancelled and cancelled():
                batch.cancelled = True
                break
            if excluded and path.resolve() in excluded:
                batch.excluded_entries += 1
                continue
            if len(batch.files) >= self.config.max_files:
                batch.truncated = True
                batch.issues.append(f"Limite de {self.config.max_files} fichiers atteinte.")
                break
            report = self.scan_file(path, cancelled)
            batch.files.append(report)
            if progress:
                progress(report)
            if report.status == "cancelled":
                batch.cancelled = True
                break
        if cancelled and cancelled():
            batch.cancelled = True
        batch.finished_at = timestamp()
        return batch
