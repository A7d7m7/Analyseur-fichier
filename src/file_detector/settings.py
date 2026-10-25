import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import ScanConfig


def default_settings_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "analyseur-fichier" / "settings.json"


@dataclass(frozen=True)
class Preferences:
    scan: ScanConfig = field(default_factory=ScanConfig)
    rules_dir: str = ""


def load_preferences(path: Path) -> Preferences:
    if not path.exists():
        return Preferences()
    with path.open("rb") as handle:
        data = handle.read(65537)
    if len(data) > 65536:
        raise ValueError("Fichier de préférences trop volumineux.")
    raw = json.loads(data)
    if raw.get("schema_version") != 1 or not isinstance(raw.get("rules_dir"), str):
        raise ValueError("Format des préférences invalide.")
    return Preferences(ScanConfig(**raw["scan"]), raw["rules_dir"])


def save_preferences(path: Path, preferences: Preferences) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(
                {"schema_version": 1, **asdict(preferences)}, handle, ensure_ascii=False, indent=2
            )
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
