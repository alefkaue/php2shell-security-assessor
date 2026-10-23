from argparse import ArgumentParser
from datetime import date
from pathlib import Path
import subprocess
import sys
from .core import assess, read_ini
from .inventory import load_inventory, inspect_local
from .report import render, write_reports


def main(argv=None):
    parser = ArgumentParser(description="Assess PHP inventory offline against reviewed PHP2Shell advisories. No network probes.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--inventory", type=Path, help="CSV or JSON inventory")
    source.add_argument("--local", action="store_true", help="inspect the explicitly selected local CLI binary only")
    source.add_argument("--docker-inspect", type=Path, help="offline docker inspect JSON (tags are inconclusive)")
    source.add_argument("--sbom", type=Path, help="offline CycloneDX JSON")
    parser.add_argument("--php-binary", default="php")
    parser.add_argument("--php-ini", type=Path, help="single local configuration file; only with --local")
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    parser.add_argument("--out", type=Path, default=Path("reports"))
    parser.add_argument("--format", choices=["all", "json", "md", "html"], default="all")
    parser.add_argument("--fail-on-risk", action="store_true", help="exit 1 for high/critical inventory findings")
    args = parser.parse_args(argv)
    if args.php_ini and not args.local:
        parser.error("--php-ini requires --local; per-asset config can be supplied in JSON")
    try:
        input_hash = None
        if args.local:
            assets = [inspect_local(args.php_binary)]
            if args.php_ini:
                assets[0]["config"] = read_ini(args.php_ini)
        else:
            path = args.inventory or args.docker_inspect or args.sbom
            kind = "docker" if args.docker_inspect else "sbom" if args.sbom else "inventory"
            assets, input_hash = load_inventory(path, kind)
        report = render([assess(a, args.as_of) for a in assets], input_hash)
        write_reports(report, args.out, ["json", "md", "html"] if args.format == "all" else [args.format])
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    for a in report["assets"]:
        # ASCII escape control sequences from operator input in terminal output.
        name = ascii(a["id"])[1:-1]
        print(f"{name:<24} {a['status']:<22} {a['severity']}")
    print(f"Reports: {args.out}")
    return int(args.fail_on_risk and any(a["severity"] in {"high", "critical"} for a in report["assets"]))


if __name__ == "__main__":
    raise SystemExit(main())
