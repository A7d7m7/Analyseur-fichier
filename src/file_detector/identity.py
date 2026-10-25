from pathlib import Path

from .models import FileReport, Finding

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}
TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".xml",
    ".html",
    ".py",
    ".js",
    ".ps1",
    ".bat",
    ".cmd",
    ".sh",
    ".vbs",
    ".yml",
    ".yaml",
    ".log",
}
EXPECTED = {
    **{e: {"MZ", "PE"} for e in PE_EXTENSIONS},
    ".pdf": {"PDF"},
    ".png": {"PNG"},
    ".jpg": {"JPEG"},
    ".jpeg": {"JPEG"},
    ".gif": {"GIF"},
    ".zip": {"ZIP"},
    ".docx": {"ZIP"},
    ".xlsx": {"ZIP"},
    ".pptx": {"ZIP"},
    ".jar": {"ZIP"},
    ".odt": {"ZIP"},
    ".ods": {"ZIP"},
}
DECOYS = {".pdf", ".jpg", ".jpeg", ".png", ".txt", ".doc", ".docx", ".xls", ".xlsx"}
ACTIVE = PE_EXTENSIONS | {".ps1", ".bat", ".cmd", ".vbs", ".js", ".lnk"}


def detect_format(data: bytes) -> str:
    signatures = [
        (b"MZ", "MZ"),
        (b"%PDF-", "PDF"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"PK\x03\x04", "ZIP"),
        (b"PK\x05\x06", "ZIP"),
        (b"PK\x07\x08", "ZIP"),
        (b"\x7fELF", "ELF"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"),
    ]
    return next((name for signature, name in signatures if data.startswith(signature)), "UNKNOWN")


def analyze_identity(report: FileReport, data: bytes) -> None:
    suffixes = [s.lower() for s in Path(report.name).suffixes]
    report.extension = suffixes[-1] if suffixes else ""
    report.format = detect_format(data)
    report.checks["identity"] = "complete"
    if report.extension in ACTIVE and any(s in DECOYS for s in suffixes[:-1]):
        report.findings.append(
            Finding(
                "double_extension",
                "identity",
                "medium",
                "Extension potentiellement trompeuse",
                "Une extension de document précède une extension active. Le nom peut tromper le lecteur.",
                [report.name, f"Extension finale : {report.extension}"],
                20,
            )
        )
    expected = EXPECTED.get(report.extension)
    if expected and report.format not in expected:
        report.findings.append(
            Finding(
                "format_mismatch",
                "identity",
                "medium",
                "Extension et signature incohérentes",
                "Le début du fichier ne correspond pas au format annoncé ; un fichier tronqué peut aussi l'expliquer.",
                [f"Extension : {report.extension}", f"Signature : {report.format}"],
                20,
            )
        )
    elif report.format == "MZ" and report.extension not in PE_EXTENSIONS:
        report.findings.append(
            Finding(
                "executable_disguised",
                "identity",
                "medium",
                "Signature MZ sous une autre extension",
                "La signature évoque un exécutable DOS/Windows. L'analyse PE doit confirmer sa structure.",
                [f"Extension : {report.extension or '(aucune)'}", "Signature : MZ"],
                25,
            )
        )
    if report.format == "UNKNOWN" and report.extension in TEXT_EXTENSIONS:
        try:
            data.decode("utf-8-sig")
            if b"\x00" not in data:
                report.format = "TEXT"
        except UnicodeDecodeError:
            pass
    if report.format in {"UNKNOWN", "ELF", "OLE"}:
        report.status = "unsupported"
        report.issues.append(
            "Format sans analyse spécialisée dans cette version ; empreinte et YARA restent disponibles."
        )
    elif report.format not in {"MZ", "PE"}:
        report.checks["coverage"] = (
            "Signature, nom, empreinte et YARA uniquement ; contenu interne non interprété."
        )
