"""Explicit local inputs only. No downloads, shell commands or service probes."""
from pathlib import Path
import csv
import io
import json
import subprocess


def load_inventory(path: Path, kind: str = "inventory") -> tuple[list[dict], str]:
    import hashlib
    with path.open("rb") as stream:
        content = stream.read(10_000_001)
    if len(content) > 10_000_000:
        raise ValueError("inventory exceeds 10 MB")
    text = content.decode("utf-8-sig")
    if kind == "docker":
        inspect = json.loads(text)
        if not isinstance(inspect, list):
            raise ValueError("docker inspect export must be a list")
        assets = []
        for i, item in enumerate(inspect):
            image = str(item.get("Config", {}).get("Image", "unknown"))
            # Never infer a trusted runtime from a mutable image tag.
            import re
            match = re.search(r"(?:^|/)php:(\d+\.\d+\.\d+[^ /]*)", image)
            assets.append({"id": item.get("Name", f"container-{i}"),
                           "version": match.group(1) if match else "",
                           "evidence_kind": "docker_tag", "evidence": "Offline docker inspect image tag; not a runtime measurement",
                           "exposure": "unknown"})
    elif kind == "sbom":
        bom = json.loads(text)
        if bom.get("bomFormat") != "CycloneDX":
            raise ValueError("only CycloneDX JSON is supported")
        assets = [{"id": x.get("bom-ref", f"php-component-{i}"), "version": x.get("version", ""),
                   "evidence_kind": "sbom", "evidence": "Supplied CycloneDX component", "exposure": "unknown"}
                  for i, x in enumerate(bom.get("components", []))
                  if x.get("name", "").lower() in {"php", "php-src"}]
    elif path.suffix.lower() == ".csv":
        assets = list(csv.DictReader(io.StringIO(text)))
        for asset in assets:
            asset["vendor_package"] = asset.get("vendor_package", "").lower() in {"true", "1", "yes"}
    else:
        assets = json.loads(text)
    if not isinstance(assets, list) or len(assets) > 10_000:
        raise ValueError("expected a JSON array or CSV, at most 10000 assets")
    seen = set()
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("id"), str) or not asset["id"].strip():
            raise ValueError("each asset needs a non-empty string id")
        if asset["id"] in seen:
            raise ValueError("duplicate asset id: " + asset["id"])
        seen.add(asset["id"])
    if not assets:
        raise ValueError("no PHP assets found; empty input is not proof of a clean environment")
    return assets, hashlib.sha256(content).hexdigest()


def inspect_local(binary: str = "php") -> dict:
    # -n ignores all configuration files; -v prints version without executing application code.
    proc = subprocess.run([binary, "-n", "-v"], capture_output=True, text=True, timeout=10,
                          check=False, shell=False)
    if proc.returncode != 0:
        raise ValueError("local PHP binary did not return a successful version response")
    import re
    match = re.search(r"^PHP\s+([^\s]+)", proc.stdout, re.M)
    return {"id": "local-cli", "version": match.group(1) if match else "",
            "sapi": "cli", "evidence_kind": "local_cli", "exposure": "unknown",
            "evidence": "Explicit local binary invoked with -n -v; no web runtime inspected"}
