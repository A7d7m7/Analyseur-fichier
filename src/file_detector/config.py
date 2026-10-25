import math
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanConfig:
    max_bytes: int = 64 * 1024 * 1024
    max_files: int = 10000
    recursive: bool = True
    yara_timeout: int = 5
    analysis_timeout: float = 15
    memory_mb: int = 512
    exclude_patterns: tuple[str, ...] = (".git", ".venv", "__pycache__")

    def __post_init__(self):
        for value in (self.max_bytes, self.max_files, self.yara_timeout, self.memory_mb):
            if type(value) is not int or value <= 0:
                raise ValueError("Les limites entières doivent être strictement positives.")
        if self.memory_mb < 64:
            raise ValueError("Le budget mémoire doit être d'au moins 64 Mio.")
        if (
            type(self.analysis_timeout) not in (int, float)
            or not math.isfinite(self.analysis_timeout)
            or self.analysis_timeout <= 0
        ):
            raise ValueError("Le délai global doit être un nombre positif fini.")
        if type(self.recursive) is not bool:
            raise ValueError("Le réglage de récursion doit être un booléen.")
        if not isinstance(self.exclude_patterns, (list, tuple)) or any(
            not isinstance(p, str) or not p.strip() for p in self.exclude_patterns
        ):
            raise ValueError("Les exclusions doivent être une liste de motifs non vides.")
        object.__setattr__(self, "exclude_patterns", tuple(self.exclude_patterns))
