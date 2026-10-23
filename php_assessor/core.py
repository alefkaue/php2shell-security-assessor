"""Conservative decisions with independent lifecycle, version and exposure evidence."""
from __future__ import annotations
from datetime import date
from pathlib import Path
import json
import re

ADVISORY = json.loads(Path(__file__).with_name("advisory.json").read_text(encoding="utf-8"))
TRUSTED_KINDS = {"inventory", "local_cli", "sbom"}
EXPOSURES = {"internet", "internal", "offline", "unknown"}
CONFIG_KEYS = {"memory_limit", "post_max_size", "upload_max_filesize",
               "session.upload_progress.enabled", "fatal_error_backtraces", "display_errors", "expose_php"}


def parse_version(raw: str) -> tuple[tuple[int, int, int] | None, str]:
    match = re.fullmatch(r"(?:PHP\s+)?(\d{1,3})\.(\d{1,3})\.(\d{1,5})([^\r\n]*)", raw.strip())
    if not match:
        return None, "unparseable"
    version = tuple(int(x) for x in match.group(1, 2, 3))
    suffix = match.group(4).strip()
    if suffix and re.match(r"(?:[-~]?(?:alpha|beta|RC|dev))", suffix, re.I):
        return version, "prerelease"
    if suffix and not re.fullmatch(r"[-+~][A-Za-z0-9.+:~_-]+", suffix):
        return None, "unparseable"
    return version, "vendor" if suffix else "stable"


def read_ini(path: Path) -> dict[str, str]:
    """Read an explicitly supplied file; never execute PHP configuration."""
    if path.stat().st_size > 1_000_000:
        raise ValueError("php.ini exceeds 1 MB")
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        if key in CONFIG_KEYS:
            # These scalar directives do not require PHP expression evaluation.
            value = value.split(";", 1)[0].strip().strip('"\'')
            result[key] = value[:100]
    return result


def config_findings(config: dict, branch: str) -> list[dict]:
    findings = []
    enabled = lambda x: str(x).lower().strip() in {"1", "on", "true", "yes"}
    def add(code, severity, message):
        findings.append({"id": code, "severity": severity, "message": message})
    if enabled(config.get("session.upload_progress.enabled", "")):
        add("UPLOAD_PROGRESS_PATH", "medium", "Confirmed session paths remain enabled. Vendor temporary advice disables upload progress before parsing and restarts ALL workers; this is not a complete fix.")
    if branch == "8.5" and enabled(config.get("fatal_error_backtraces", "")):
        add("FATAL_BACKTRACE_PATH", "medium", "Review the PHP 8.5 fatal-backtrace path; the vendor documents disabling it and restarting workers as a partial measure only.")
    if "memory_limit" in config:
        add("OOM_REVIEW", "info", "Review memory and request-size controls with the official advisory. memory_limit=-1 is not a complete fix and can increase availability risk; no automatic changes are made.")
    if enabled(config.get("display_errors", "")):
        add("ERROR_DISCLOSURE", "low", "Production error display may reveal information; hiding diagnostics does not fix these CVEs.")
    if enabled(config.get("expose_php", "")):
        add("VERSION_DISCLOSURE", "low", "Review PHP version disclosure. Hiding a banner does not remediate the underlying issue.")
    return findings


def assess(asset: dict, as_of: date | None = None) -> dict:
    as_of = as_of or date.today()
    if as_of < date.fromisoformat(ADVISORY["reviewed_on"]):
        raise ValueError("assessment date precedes the reviewed advisory snapshot")
    raw = str(asset.get("version", ""))
    version, flavor = parse_version(raw)
    branch = ".".join(map(str, version[:2])) if version else ""
    definition = ADVISORY["branches"].get(branch)
    kind = asset.get("evidence_kind", "inventory")
    exposure = asset.get("exposure", "unknown")
    if exposure not in EXPOSURES:
        raise ValueError("exposure must be internet, internal, offline or unknown")
    if kind not in TRUSTED_KINDS | {"http_header", "docker_tag", "unknown"}:
        raise ValueError("unsupported evidence_kind")
    unsupported = bool(kind in TRUSTED_KINDS and version and (version[:2] <= (8, 1) or
                        definition and as_of > date.fromisoformat(definition["security_end"])))
    status, assessment, severity = "unknown", "unconfirmed", "review"
    reasons, actions = [], []
    fixed = definition["fixed"] if definition else None
    fix = asset.get("vendor_fix") or {}
    if not isinstance(fix, dict):
        raise ValueError("vendor_fix must be an object")
    vendor_attestation = (fix.get("verified") is True and
        set(ADVISORY["ids"]).issubset(set(fix.get("advisories", []))) and
        isinstance(fix.get("reference"), str) and fix["reference"].startswith("https://"))
    if not version:
        reasons.append("No complete PHP version could be established.")
    elif kind not in TRUSTED_KINDS:
        reasons.append("Header/tag metadata is not proof of the installed runtime or applied patches.")
    elif vendor_attestation:
        status, assessment, severity = "vendor_fix_recorded", "operator_attested_vendor_fix", "info"
        reasons.append("Operator supplied a verified vendor reference covering both CVEs; the tool did not independently authenticate that reference.")
    elif flavor == "prerelease":
        reasons.append("Prerelease: stable branch thresholds must not be applied; review the specific release advisory.")
    elif not definition:
        reasons.append("This branch has no stable threshold in the reviewed advisory snapshot.")
        if unsupported:
            assessment = "potentially_affected_eol"
    elif version >= tuple(map(int, fixed.split("."))):
        status, assessment, severity = "fixed_upstream", "version_in_fixed_range", "info"
        reasons.append("The supplied version is in the upstream fixed range for BOTH listed CVEs, not a guarantee of general security.")
    elif flavor == "vendor" or asset.get("vendor_package") is True:
        status, assessment, severity = "needs_vendor_review", "backport_unconfirmed", "high"
        reasons.append("Upstream version precedes the fix, but a distributor may have backported it. Verify the exact package build with the vendor.")
    else:
        status, assessment = "affected_version", "upstream_version_affected"
        severity = "critical" if exposure == "internet" else "high"
        reasons.append("Supplied stock version falls within the published affected range; this does not establish exploitability or compromise.")
    if unsupported:
        status = "unsupported"
        severity = "high"
        reasons.append("Branch is outside upstream security support as of the selected assessment date, even if an incident-specific vendor fix exists.")
    if assessment not in {"version_in_fixed_range", "operator_attested_vendor_fix"}:
        actions.extend(["Verify the runtime used by EACH web worker, container and bundled application.",
                        "Apply the supported upstream release or a documented vendor backport; restart every worker and verify the running build."])
        if exposure == "internet":
            actions.append("Prioritise this internet-facing asset; if patching is delayed, assess isolation and the vendor's partial mitigations.")
    if unsupported:
        actions.append("Plan migration to a supported branch; an emergency source backport does not restore upstream lifecycle support.")
    if kind == "local_cli":
        reasons.append("Local CLI inspection does not identify PHP-FPM, mod_php or remote web-worker versions.")
    if kind == "sbom":
        reasons.append("SBOM identifies a component, not proof that a running web service uses that component.")
    if (as_of - date.fromisoformat(ADVISORY["reviewed_on"])).days > 30:
        reasons.append("Advisory snapshot is more than 30 days old. Revalidate upstream and lifecycle data.")
    config = asset.get("config") or {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object")
    return {"id": str(asset["id"]), "version": raw, "evidence_kind": kind,
            "evidence": str(asset.get("evidence", "Operator-supplied inventory")),
            "exposure": exposure, "sapi": str(asset.get("sapi", "unknown")),
            "status": status, "cve_assessment": assessment, "severity": severity,
            "unsupported": unsupported, "fixed_upstream": fixed,
            "as_of": as_of.isoformat(), "reasons": reasons, "recommendations": actions,
            "vendor_fix": fix if vendor_attestation else None,
            "config": {k: str(v) for k, v in config.items() if k in CONFIG_KEYS},
            "config_findings": config_findings(config, branch),
            "configuration_scope": "Supplied scalar values only; pool, directory and application overrides may differ."}
