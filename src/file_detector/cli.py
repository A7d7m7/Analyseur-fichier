import argparse
import math
import sys
from pathlib import Path

from . import __version__
from .reports import write_report
from .scanner import ScanConfig, Scanner
from .scoring import score_explanation


def positive_int(value: str) -> int:
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("La valeur doit être strictement positive.")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyse statique locale de fichiers, sans exécution."
    )
    parser.add_argument("target", type=Path, help="Fichier ou dossier à analyser")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--json", type=Path, help="Destination du rapport JSON")
    parser.add_argument("--html", type=Path, help="Destination du rapport HTML")
    parser.add_argument(
        "--rules", type=Path, help="Dossier de règles YARA remplaçant les règles intégrées"
    )
    parser.add_argument(
        "--max-size-mb",
        type=positive_int,
        default=64,
        help="Limite par fichier en Mio (défaut : 64)",
    )
    parser.add_argument("--max-files", type=positive_int, default=10000)
    parser.add_argument(
        "--yara-timeout", type=positive_int, default=5, help="Secondes par analyse YARA"
    )
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument(
        "--timeout",
        type=float,
        default=15,
        help="Délai global par fichier en secondes (défaut : 15)",
    )
    parser.add_argument(
        "--memory-mb",
        type=positive_int,
        default=512,
        help="Budget mémoire par processus en Mio, minimum 64",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Motif à exclure, répétable : '*.tmp', 'build', 'cache/*'",
    )
    parser.add_argument(
        "--explain", action="store_true", help="Afficher les contributions au score"
    )
    parser.add_argument("--quiet", action="store_true", help="Masquer la progression")
    parser.add_argument("--force", action="store_true", help="Remplacer les rapports existants")
    args = parser.parse_args(argv)
    destinations = [p for p in (args.json, args.html) if p is not None]
    if len({p.resolve() for p in destinations}) != len(destinations):
        parser.error("Les rapports JSON et HTML doivent avoir des destinations différentes.")
    for path in destinations:
        if path.resolve() == args.target.resolve():
            parser.error("La destination ne peut pas remplacer la cible analysée.")
        if path.exists() and not args.force:
            parser.error(f"Le rapport existe déjà : {path}. Utiliser --force pour le remplacer.")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout doit être un nombre positif fini.")
    try:
        config = ScanConfig(
            max_bytes=args.max_size_mb * 1024 * 1024,
            max_files=args.max_files,
            recursive=not args.no_recursive,
            yara_timeout=args.yara_timeout,
            analysis_timeout=args.timeout,
            memory_mb=args.memory_mb,
            exclude_patterns=ScanConfig().exclude_patterns + tuple(args.exclude),
        )
    except ValueError as exc:
        parser.error(str(exc))
    scanner = Scanner(config, args.rules)
    counter = 0

    def progress(report):
        nonlocal counter
        counter += 1
        if not args.quiet:
            # repr empêche un nom de fichier de produire des commandes de terminal ANSI.
            print(
                f"[{counter}] {report.name!a} : {report.score}/100 · {report.risk} ({report.status})",
                file=sys.stderr,
            )
        if args.explain:
            print(f"Calcul du score pour {report.name!a} :")
            for line in score_explanation(report):
                print(f"  {line}")

    try:
        report = scanner.scan(args.target, progress=progress, exclude=set(destinations))
        for destination, kind in [(args.json, "json"), (args.html, "html")]:
            if destination is not None:
                write_report(report, destination, kind, overwrite=args.force)
        summary = report.to_dict()["summary"]
        print(
            f"{summary['total']} fichier(s) · {summary['with_findings']} avec indices · "
            f"{summary['incomplete']} analyse(s) non complète(s)."
        )
        if report.excluded_entries:
            print(
                f"{report.excluded_entries} entrée(s) exclue(s) (un sous-dossier compte pour une entrée)."
            )
        print("Score heuristique, pas une probabilité de malware.")
        for issue in report.issues:
            print(f"Attention : {issue!a}", file=sys.stderr)
        if report.issues or report.truncated or report.cancelled or summary["incomplete"]:
            return 2
        return 1 if any(f.score >= 25 for f in report.files) else 0
    except (OSError, ValueError) as exc:
        print(f"Erreur : {str(exc)!a}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Analyse interrompue.", file=sys.stderr)
        return 130
