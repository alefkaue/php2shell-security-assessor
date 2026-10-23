# Research notes — reviewed 2026-10-23

## Evidence and chronology

The PHP Foundation describes the announcement on October 20 and the accelerated release on
October 21, 2026. It attributes the fixes to PHP's maintainers and collaborating researchers;
this repository makes no vulnerability-discovery claim. The incident is commonly grouped under
the PHP2Shell name; use CVE IDs when making a technical statement.

The upstream advisories describe two separate engine issues:

- **CVE-2026-109618:** OOM handling may interrupt initialization, after which cleanup treats invalid
  internal data as valid. This is memory corruption, not an ordinary application SQL injection.
- **CVE-2026-109619:** request-associated global state can outlive its backing memory and be consumed
  during a subsequent request. This is stale-state/use-after-free behavior.

The published impact includes unauthenticated RCE under relevant conditions. A matching version
does not prove a particular deployment is exploitable, and a crash is not proof of RCE.
Do not infer active compromise from the existence of public discussion or a PoC.

## Stable fix baseline

| Branch | First fixed stable version | Upstream security support through |
|---|---|---|
| 8.2 | 8.2.35 | 2026-12-31 |
| 8.3 | 8.3.36 | 2027-12-31 |
| 8.4 | 8.4.27 | 2028-12-31 |
| 8.5 | 8.5.12 | 2029-12-31 |

Source packages with vendor backports require package-specific evidence. An emergency backport
to an EOL branch does not extend its upstream lifecycle. Prerelease 8.6 builds require their own
release-specific assessment and are not classified using these stable thresholds.

## Operational interpretation

Inventory web handlers, containers, embedded runtimes and the CLI separately. Prioritize exposed
web deployments, especially the mod_php path highlighted by maintainers, without assuming other
SAPIs are immune. Apply the appropriate vendor/upstream update, restart the actual workers and
verify the running build, not merely a downloaded package or an image tag.

Temporary vendor measures cover specific paths only. The project records configuration facts
but does not generate an automatic `php.ini` patch. Setting unlimited PHP memory has availability
trade-offs; request-size and process/container resource controls require deployment review.
Disabling upload progress or a particular error path does not fix all variants. Hiding errors does
not repair memory management. If updating is blocked, evaluate isolation with the incident owner.

## Sources

- [PHP Foundation: release context](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- [PHP announcement and detailed temporary measures](https://www.php.net/archive/2026.php)
- [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [Stale global state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [CERT-EU](https://www.cert.europa.eu/publications/security-advisories/2026-018)
- [NCSC](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)
- [PHP support schedule](https://www.php.net/supported-versions.php)

These links were consulted directly. The bundled snapshot is reviewed data, not an automatically
refreshed vulnerability feed. No exploit code or original third-party infrastructure is included.
