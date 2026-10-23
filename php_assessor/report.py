"""Static, escaped reports. Never embeds supplied data as active HTML."""
from collections import Counter
from html import escape
import json
from pathlib import Path
from .core import ADVISORY


def render(results, input_hash=None):
    return {"tool": "php2shell-security-assessor", "schema_version": 1,
            "scope": "Offline inventory assessment; no exploitation or proof of compromise.",
            "advisory_reviewed_on": ADVISORY["reviewed_on"], "cves": ADVISORY["ids"],
            "advisory_cvss_v4": ADVISORY["cvss_v4"],
            "severity_meaning": "Asset severity is local remediation priority, not a recalculated CVSS score.",
            "input_sha256": input_hash, "references": ADVISORY["references"],
            "summary": dict(Counter(x["status"] for x in results)), "assets": results}


def markdown(report):
    clean = lambda s: str(s).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    lines = ["# PHP security assessment", "", report["scope"], "",
             f"Advisory snapshot: {report['advisory_reviewed_on']}",
             f"Published advisory CVSS v4: {report['advisory_cvss_v4']}. {report['severity_meaning']}",
             f"Input SHA-256: {report['input_sha256'] or 'local measurement'}", "",
             "| Asset | Version | Classification | Severity | Exposure |",
             "|---|---|---|---|---|"]
    for a in report["assets"]:
        lines.append("| " + " | ".join(clean(a[k]) for k in ("id", "version", "status", "severity", "exposure")) + " |")
    for a in report["assets"]:
        lines += ["", "## " + clean(a["id"]), "", "Evidence: " + clean(a["evidence"])]
        lines += ["- " + clean(x) for x in a["reasons"] + a["recommendations"]]
        lines += ["- " + clean(x["id"] + ": " + x["message"]) for x in a["config_findings"]]
    lines += ["", "## Official references", *["- " + x for x in report["references"]]]
    return "\n".join(lines) + "\n"


def html_report(report):
    # A static document with escaped text; no external scripts, fonts or tracking.
    return ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<title>PHP security assessment</title><style>body{max-width:1000px;margin:32px auto;'
            'padding:0 20px;font:16px system-ui;color:#172b35;background:#fff}pre{white-space:pre-wrap;'
            'overflow-wrap:anywhere;line-height:1.55;border-left:4px solid #216955;padding:18px;background:#f5f7f8}'
            '</style><h1>PHP security assessment</h1><pre>' + escape(markdown(report)) + '</pre></html>')


def write_reports(report: dict, out: Path, formats: list[str]):
    out.mkdir(parents=True, exist_ok=True)
    content = {"json": json.dumps(report, indent=2, ensure_ascii=False) + "\n",
               "md": markdown(report), "html": html_report(report)}
    for fmt in formats:
        (out / ("assessment." + fmt)).write_text(content[fmt], encoding="utf-8")
