import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch
from php_assessor.core import assess, parse_version, read_ini
from php_assessor.inventory import load_inventory, inspect_local
from php_assessor.report import render, html_report
from php_assessor.__main__ import main

DAY = date(2026, 10, 23)
def asset(version, **kwargs):
    return {"id": "lab", "version": version, **kwargs}

class AssessmentTests(unittest.TestCase):
    def test_all_branch_boundaries(self):
        for vulnerable, fixed in [("8.2.34", "8.2.35"), ("8.3.35", "8.3.36"),
                                  ("8.4.26", "8.4.27"), ("8.5.11", "8.5.12")]:
            with self.subTest(branch=fixed):
                self.assertEqual(assess(asset(vulnerable), DAY)["status"], "affected_version")
                self.assertEqual(assess(asset(fixed), DAY)["status"], "fixed_upstream")

    def test_version_comparison_is_numeric(self):
        self.assertEqual(assess(asset("8.5.100"), DAY)["status"], "fixed_upstream")

    def test_internet_priority_does_not_prove_exploitation(self):
        result = assess(asset("8.4.26", exposure="internet"), DAY)
        self.assertEqual(result["severity"], "critical")
        self.assertIn("does not establish exploitability", " ".join(result["reasons"]))

    def test_untrusted_banners_and_tags_never_confirm_affected(self):
        for kind in ("http_header", "docker_tag", "unknown"):
            self.assertEqual(assess(asset("8.5.11", evidence_kind=kind), DAY)["status"], "unknown")
            self.assertEqual(assess(asset("8.1.34", evidence_kind=kind), DAY)["status"], "unknown")

    def test_missing_malformed_future_and_prerelease(self):
        for version in ("", "PHP", "8.2", "x8.2.35", "8.6.1", "8.5.12RC1", "8.6.0RC4", "8.5.12garbage"):
            self.assertEqual(assess(asset(version), DAY)["status"], "unknown", version)

    def test_distributor_packages_need_review(self):
        for data in (asset("8.2.30-1+deb12u9"), asset("8.2.30", vendor_package=True)):
            self.assertEqual(assess(data, DAY)["status"], "needs_vendor_review")

    def test_vendor_attestation_requires_both_cves_and_reference(self):
        fix = {"verified": True, "advisories": ["CVE-2026-109618", "CVE-2026-109619"],
               "reference": "https://vendor.example/advisory/42"}
        self.assertEqual(assess(asset("8.2.30-1", vendor_fix=fix), DAY)["status"], "vendor_fix_recorded")
        fix["advisories"] = ["CVE-2026-109618"]
        self.assertEqual(assess(asset("8.2.30-1", vendor_fix=fix), DAY)["status"], "needs_vendor_review")

    def test_eol_survives_an_incident_specific_fix(self):
        self.assertEqual(assess(asset("8.1.34"), DAY)["status"], "unsupported")
        self.assertEqual(assess(asset("8.2.35"), date(2027, 1, 1))["status"], "unsupported")
        self.assertEqual(assess(asset("8.2.35"), date(2026, 12, 31))["status"], "fixed_upstream")

    def test_stale_snapshot_warns(self):
        self.assertIn("30 days", " ".join(assess(asset("8.5.12"), date(2027, 1, 1))["reasons"]))

    def test_snapshot_cannot_claim_knowledge_before_review(self):
        with self.assertRaises(ValueError):
            assess(asset("8.5.12"), date(2026, 10, 20))

    def test_config_is_advisory_not_a_fixed_version_claim(self):
        a = asset("8.5.11", config={"memory_limit": "-1", "session.upload_progress.enabled": "0"})
        self.assertEqual(assess(a, DAY)["status"], "affected_version")

    def test_config_redacts_unrelated_values(self):
        a = asset("8.5.12", config={"db_password": "do-not-export", "expose_php": "On"})
        self.assertNotIn("do-not-export", json.dumps(assess(a, DAY)))

    def test_invalid_input_enums(self):
        with self.assertRaises(ValueError):
            assess(asset("8.5.12", exposure="maybe"), DAY)

class FileAndCLITests(unittest.TestCase):
    def test_inventory_csv_and_provenance(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "inventory.csv"
            p.write_text("id,version,vendor_package\nserver,8.2.30,true\n", encoding="utf-8")
            assets, digest = load_inventory(p)
            self.assertTrue(assets[0]["vendor_package"])
            self.assertEqual(len(digest), 64)

    def test_empty_and_duplicate_inputs_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "input.json"
            for data in ([], [{"id": "x"}, {"id": "x"}], [{"version": "8.5.12"}]):
                p.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_inventory(p)

    def test_docker_does_not_treat_tags_as_runtime_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "inspect.json"
            p.write_text('[{"Name":"demo","Config":{"Image":"php:8.5.11-fpm"}}]', encoding="utf-8")
            assets, _ = load_inventory(p, "docker")
            self.assertEqual(assess(assets[0], DAY)["status"], "unknown")

    def test_sbom_does_not_match_phpunit(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "bom.json"
            p.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
                {"name": "php", "version": "8.4.27"}, {"name": "phpunit", "version": "10.0.0"}]}), encoding="utf-8")
            assets, _ = load_inventory(p, "sbom")
            self.assertEqual(len(assets), 1)

    def test_ini_duplicates_and_unknown_directives(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "php.ini"
            p.write_text('; ignore\n[PHP]\nmemory_limit = 128M\nsecret = hidden\nmemory_limit = -1 ; note\n', encoding="utf-8")
            self.assertEqual(read_ini(p), {"memory_limit": "-1"})

    def test_report_html_escapes_input(self):
        report = render([assess({"id": "<script>alert(1)</script>", "version": "8.5.11"}, DAY)])
        self.assertEqual(report["advisory_cvss_v4"], 9.2)
        self.assertIn("priority", report["severity_meaning"])
        self.assertNotIn("<script>", html_report(report))
        self.assertIn("&lt;script&gt;", html_report(report))

    def test_local_is_explicit_and_shell_free(self):
        with patch("php_assessor.inventory.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "PHP 8.5.12 (cli)\n"
            self.assertEqual(inspect_local()["version"], "8.5.12")
            self.assertFalse(run.call_args.kwargs["shell"])

    def test_cli_writes_three_reports_and_risk_exit_code(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            p = root / "input.json"
            p.write_text('[{"id":"lab","version":"8.5.11","exposure":"internet"}]', encoding="utf-8")
            self.assertEqual(main(["--inventory", str(p), "--as-of", "2026-10-23", "--out", str(root / "out"), "--fail-on-risk"]), 1)
            for ext in ("json", "md", "html"):
                self.assertTrue((root / "out" / ("assessment." + ext)).is_file())

    def test_cli_invalid_json_returns_two(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "bad.json"
            p.write_text("{", encoding="utf-8")
            self.assertEqual(main(["--inventory", str(p)]), 2)

if __name__ == "__main__":
    unittest.main()
