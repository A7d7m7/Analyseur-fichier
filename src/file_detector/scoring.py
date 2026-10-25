from collections import defaultdict

from .models import FileReport

# Les indices d'une même famille ne doivent pas multiplier artificiellement le score.
CATEGORY_CAPS = {"identity": 30, "imports": 35, "structure": 35, "yara": 30, "test": 0}
CATEGORY_LABELS = {
    "identity": "Identité",
    "imports": "Imports PE",
    "structure": "Structure PE",
    "yara": "YARA",
    "test": "Marqueurs de test",
}


def score_report(report: FileReport) -> None:
    totals: dict[str, int] = defaultdict(int)
    seen = set()
    duplicates = []
    for finding in report.findings:
        if finding.code not in seen:
            totals[finding.category] += max(0, finding.points)
            seen.add(finding.code)
        else:
            duplicates.append(finding.code)
    categories = [
        {
            "category": c,
            "label": CATEGORY_LABELS.get(c, c),
            "raw_points": n,
            "cap": CATEGORY_CAPS.get(c, 20),
            "contribution": min(n, CATEGORY_CAPS.get(c, 20)),
        }
        for c, n in sorted(totals.items())
    ]
    subtotal = sum(c["contribution"] for c in categories)
    report.score = min(100, subtotal)
    report.score_breakdown = {
        "categories": categories,
        "subtotal": subtotal,
        "global_cap": 100,
        "global_reduction": max(0, subtotal - 100),
        "total": report.score,
        "duplicate_codes_ignored": duplicates,
    }
    if report.score >= 60:
        report.risk = "élevé"
    elif report.score >= 25:
        report.risk = "modéré"
    elif report.score:
        report.risk = "faible"
    elif report.status != "complete":
        report.risk = "indéterminé"
    else:
        report.risk = "aucun indice détecté"


def score_explanation(report: FileReport) -> list[str]:
    breakdown = report.score_breakdown
    if not breakdown:
        return ["Détail du score indisponible."]
    lines = [
        f"{c['label']} : {c['raw_points']} points bruts → {c['contribution']} retenus (plafond {c['cap']})"
        for c in breakdown["categories"]
    ]
    if not lines:
        lines.append("Aucun indice contribuant au score.")
    lines.append(
        f"Sous-total : {breakdown['subtotal']} ; plafond global : 100 ; score final : {report.score}/100."
    )
    if breakdown["duplicate_codes_ignored"]:
        lines.append("Codes en double ignorés : " + ", ".join(breakdown["duplicate_codes_ignored"]))
    return lines
