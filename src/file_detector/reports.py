import html
import json
import os
import tempfile
from pathlib import Path

from .models import ScanReport
from .scoring import score_explanation

DISCLAIMER = "Score heuristique sur 100, pas une probabilité de malware. Aucun indice détecté ne garantit pas l'innocuité."
STATUS_LABELS = {
    "complete": "Terminée",
    "partial": "Incomplète",
    "unsupported": "Format non pris en charge",
    "skipped": "Ignorée",
    "error": "Erreur",
    "cancelled": "Annulée",
    "timeout": "Délai dépassé",
    "resource_limit": "Limite mémoire",
}


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_html(report: ScanReport) -> str:
    summary = report.to_dict()["summary"]
    cards = []
    for item in report.files:
        score_details = "".join(f"<li>{escape(line)}</li>" for line in score_explanation(item))
        findings = (
            "".join(
                f'<li><strong>{escape(f.title)}</strong> <span class="badge">{escape(f.severity)} · +{f.points} brut</span>'
                f"<p>{escape(f.explanation)}</p><ul>"
                + "".join(f"<li><code>{escape(e)}</code></li>" for e in f.evidence)
                + "</ul></li>"
                for f in item.findings
            )
            or "<li>Aucun indice détecté par les contrôles réalisés.</li>"
        )
        issues = "".join(f"<li>{escape(issue)}</li>" for issue in item.issues)
        checks = "".join(
            f"<li><strong>{escape(k)}</strong> : {escape(v)}</li>" for k, v in item.checks.items()
        )
        pe = ""
        if item.pe:
            rows = "".join(
                f"<tr><td>{escape(s['name'])}</td><td>{s['raw_size']}</td><td>{s['entropy']}</td>"
                f"<td>{'Oui' if s['executable'] else 'Non'}</td><td>{'Oui' if s['writable'] else 'Non'}</td></tr>"
                for s in item.pe["sections"]
            )
            imports = (
                "".join(
                    f"<li><strong>{escape(i['dll'])}</strong> ({escape(i['kind'])}) : "
                    f"<code>{escape(', '.join(i['symbols']))}</code></li>"
                    for i in item.pe["imports"]
                )
                or "<li>Aucun import extrait ; cela ne prouve pas l'absence d'appels dynamiques.</li>"
            )
            warnings = "".join(f"<li>{escape(w)}</li>" for w in item.pe["parser_warnings"])
            pe = (
                f"<h3>Exécutable PE · {escape(item.pe['architecture'])}</h3>"
                '<div class="table"><table><thead><tr><th>Section</th><th>Octets</th><th>Entropie / 8</th><th>Exécutable</th><th>Inscriptible</th></tr></thead>'
                f"<tbody>{rows}</tbody></table></div><h3>Imports</h3><ul>{imports}</ul>"
                + (f"<h3>Avertissements du parseur</h3><ul>{warnings}</ul>" if warnings else "")
            )
        cards.append(
            f'<article><div class="filehead"><h2>{escape(item.name)}</h2><span class="score">{item.score}/100</span></div>'
            f"<p><strong>{escape(item.risk)}</strong> · {escape(STATUS_LABELS[item.status])} · {escape(item.format)} · {item.size if item.size is not None else '?'} octets</p>"
            f'<p class="path">{escape(item.path)}</p><p class="hash">SHA-256 : {escape(item.sha256 or "Non calculé")}</p>'
            + (f'<div class="notice"><ul>{issues}</ul></div>' if issues else "")
            + f"<h3>Calcul du score</h3><ul>{score_details}</ul>"
            + f'<h3>Indices et explications</h3><ul class="findings">{findings}</ul>'
            + f"<details><summary>Détail des contrôles et du PE</summary><ul>{checks}</ul>{pe}</details></article>"
        )
    notices = list(report.issues)
    if report.excluded_entries:
        notices.append(
            f"{report.excluded_entries} entrée(s) exclue(s), un dossier compte pour une entrée."
        )
    if report.cancelled:
        notices.append("Analyse annulée : les résultats ne couvrent qu'une partie de la sélection.")
    if report.truncated:
        notices.append("Analyse tronquée par la limite de fichiers.")
    notices_html = "".join(f"<li>{escape(issue)}</li>" for issue in notices)
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Rapport · Analyseur de fichiers</title>
<style>
:root{{color-scheme:light}}*{{box-sizing:border-box}}body{{margin:0;background:#f2f5f9;color:#182738;font:16px/1.6 system-ui,sans-serif}}main{{max-width:1100px;margin:auto;padding:44px 24px}}header{{margin-bottom:28px}}.eyebrow{{font-size:12px;letter-spacing:.16em;font-weight:700;color:#25685b}}h1{{font-size:36px;letter-spacing:-.04em;margin:8px 0}}h2{{font-size:20px;margin:0;overflow-wrap:anywhere}}h3{{font-size:15px;margin-top:24px}}p{{margin:8px 0}}.muted,.path,.hash{{color:#546476;font-size:13px;overflow-wrap:anywhere}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}}.metric,article{{background:white;border:1px solid #dbe3ec;border-radius:12px}}.metric{{padding:18px}}.metric strong{{display:block;font-size:28px}}.metric span{{font-size:13px;color:#546476}}article{{padding:24px;margin:18px 0}}.filehead{{display:flex;justify-content:space-between;align-items:center;gap:16px}}.score{{font-weight:700;background:#e8f3ef;padding:6px 12px;border-radius:8px;white-space:nowrap}}.badge{{font-size:12px;color:#546476}}code{{overflow-wrap:anywhere}}.notice{{background:#fff3d7;border-left:4px solid #c78217;padding:8px 16px;margin:16px 0}}.findings>li{{margin:16px 0}}summary{{cursor:pointer;color:#25685b;font-weight:600}}details{{border-top:1px solid #dbe3ec;padding-top:16px;margin-top:24px}}.table{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{padding:10px;text-align:left;border-bottom:1px solid #dbe3ec}}footer{{font-size:12px;color:#546476;margin-top:28px}}@media(max-width:650px){{.metrics{{grid-template-columns:repeat(2,1fr)}}main{{padding:24px 12px}}h1{{font-size:28px}}article{{padding:16px}}}}@media print{{body{{background:white}}article{{break-inside:avoid}}details{{display:block}}}}
</style></head><body><main>
<header><div class="eyebrow">ANALYSE STATIQUE · LOCALE · V{escape(report.engine_version)}</div><h1>Rapport d'analyse de fichiers</h1>
<p class="path">{escape(report.target)}</p><p class="muted">Du {escape(report.started_at)} au {escape(report.finished_at)} · Horodatage UTC</p></header>
<div class="metrics"><div class="metric"><strong>{summary["total"]}</strong><span>Fichiers examinés</span></div><div class="metric"><strong>{summary["with_findings"]}</strong><span>Avec des indices ou marqueurs</span></div><div class="metric"><strong>{summary["high_risk"]}</strong><span>Suspicion élevée</span></div><div class="metric"><strong>{summary["incomplete"]}</strong><span>Analyses non complètes</span></div></div>
<p>{escape(DISCLAIMER)}</p>{'<div class="notice"><ul>' + notices_html + "</ul></div>" if notices else ""}
{"".join(cards) or "<article>Aucun fichier analysé.</article>"}
<footer>Schéma {escape(report.schema_version)} · Points bruts plafonnés par famille avant total. Les archives et documents ne sont pas décompressés ou interprétés dans cette version.</footer>
</main></body></html>"""


def write_report(report: ScanReport, destination: Path, kind: str, overwrite: bool = False) -> Path:
    destination = Path(destination).absolute()
    if destination.resolve() == Path(report.target).resolve() or any(
        destination.resolve() == Path(f.path).resolve() for f in report.files
    ):
        raise ValueError("Un rapport ne peut pas remplacer un fichier analysé.")
    if kind not in {"json", "html"}:
        raise ValueError("Format de rapport inconnu.")
    content = (
        json.dumps(report.to_dict(), ensure_ascii=True, indent=2) + "\n"
        if kind == "json"
        else render_html(report)
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            errors="backslashreplace",
            dir=destination.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
