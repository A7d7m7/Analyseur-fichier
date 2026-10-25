from .models import FileReport, Finding


def import_findings(names: set[str]) -> list[Finding]:
    names = {n.lower() for n in names}
    groups = [
        (
            "remote_memory",
            {"virtualallocex", "writeprocessmemory", "createremotethread"},
            "Combinaison d'imports de mémoire distante",
            35,
            "Ces imports permettent d'allouer, écrire et démarrer un thread dans un autre processus. Leur présence ne prouve ni leur appel ni une intention malveillante.",
        ),
        (
            "dynamic_memory",
            {"virtualalloc", "virtualprotect", "getprocaddress"},
            "Combinaison d'imports de mémoire et résolution dynamique",
            15,
            "Cette combinaison peut participer à un chargement dynamique ; des logiciels légitimes l'utilisent aussi.",
        ),
    ]
    return [
        Finding(code, "imports", "medium", title, explanation, sorted(required), points)
        for code, required, title, points, explanation in groups
        if required <= names
    ]


def analyze_pe(report: FileReport, data: bytes) -> None:
    try:
        import pefile
    except ImportError:
        report.status = "partial"
        report.checks["pe"] = "unavailable"
        report.issues.append("Module pefile indisponible : analyse PE non réalisée.")
        return
    pe = None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )
        report.format = "PE"
        imports = []
        names = set()
        for attribute, kind in [
            ("DIRECTORY_ENTRY_IMPORT", "normal"),
            ("DIRECTORY_ENTRY_DELAY_IMPORT", "delayed"),
        ]:
            for entry in getattr(pe, attribute, []):
                symbols = []
                for symbol in entry.imports:
                    name = (
                        symbol.name.decode("utf-8", errors="replace")
                        if symbol.name
                        else f"ordinal:{symbol.ordinal}"
                    )
                    symbols.append(name)
                    names.add(name)
                imports.append(
                    {
                        "dll": entry.dll.decode("utf-8", errors="replace"),
                        "kind": kind,
                        "symbols": symbols,
                    }
                )
        report.findings.extend(import_findings(names))
        sections = []
        for index, section in enumerate(pe.sections):
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            entropy = section.get_entropy()
            executable = bool(section.Characteristics & 0x20000000)
            writable = bool(section.Characteristics & 0x80000000)
            sections.append(
                {
                    "name": name,
                    "raw_size": section.SizeOfRawData,
                    "virtual_size": section.Misc_VirtualSize,
                    "entropy": round(entropy, 4),
                    "executable": executable,
                    "writable": writable,
                    "rva": section.VirtualAddress,
                }
            )
            if entropy >= 7.2 and section.SizeOfRawData >= 1024:
                report.findings.append(
                    Finding(
                        f"high_entropy_{index}",
                        "structure",
                        "low",
                        "Section à forte entropie",
                        "Peut indiquer compression, chiffrement ou packing ; des ressources légitimes peuvent avoir la même propriété.",
                        [name, f"Entropie : {entropy:.3f}/8", f"Taille : {section.SizeOfRawData}"],
                        10,
                    )
                )
            if writable and executable:
                report.findings.append(
                    Finding(
                        f"writable_executable_{index}",
                        "structure",
                        "medium",
                        "Section inscriptible et exécutable",
                        "Ces permissions peuvent accompagner du code généré ou modifié en mémoire ; elles ne prouvent pas une activité malveillante.",
                        [name, f"Characteristics : {section.Characteristics:#x}"],
                        15,
                    )
                )
            if name.upper().startswith("UPX"):
                report.findings.append(
                    Finding(
                        f"packing_name_{index}",
                        "structure",
                        "low",
                        "Nom de section évoquant un packer",
                        "Le nom évoque UPX ; il peut être modifié et un logiciel compressé peut être légitime.",
                        [name],
                        10,
                    )
                )
        if len(pe.sections) > 12:
            report.findings.append(
                Finding(
                    "many_sections",
                    "structure",
                    "low",
                    "Nombre de sections inhabituel",
                    "Heuristique indicative ; certains outils de compilation produisent de nombreuses sections.",
                    [f"Sections : {len(pe.sections)}"],
                    5,
                )
            )
        warnings = pe.get_warnings()
        report.pe = {
            "architecture": pefile.MACHINE_TYPE.get(
                pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)
            ),
            "section_count": len(pe.sections),
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "sections": sections,
            "imports": imports,
            "parser_warnings": warnings[:20],
        }
        report.checks["pe"] = "complete"
        if warnings:
            report.status = "partial"
            report.checks["pe"] = "partial"
            report.issues.append(
                "Le parseur PE signale des anomalies : les informations extraites peuvent être incomplètes. Voir parser_warnings."
            )
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 -- isoler un échec de parseur dans un lot
        # Les entrées sont non fiables : une erreur de parseur ne doit pas arrêter le lot.
        report.status = "partial"
        report.checks["pe"] = "error"
        report.issues.append(f"Analyse PE impossible : {type(exc).__name__}: {exc}")
    finally:
        if pe is not None:
            pe.close()
