# Decision and trust model

```mermaid
flowchart TD
    A[CSV / JSON / local CLI / exported inventory] --> B[Validate IDs, provenance and evidence kind]
    B --> C{Complete stable runtime version?}
    C -->|No or metadata only| U[Unknown: gather evidence]
    C -->|Yes| D{Operator-verified vendor fix for both CVEs?}
    D -->|Yes| V[Record vendor attestation]
    D -->|No| E{Known supported branch?}
    E -->|No| L[Unknown or EOL]
    E -->|Yes| F{At or above branch baseline?}
    F -->|Yes| G[Fixed upstream range]
    F -->|No, vendor package| H[Vendor review required]
    F -->|No, stock version| I[Affected upstream version]
    V --> J[Independent lifecycle and exposure review]
    G --> J
    H --> J
    I --> J
    L --> J
    U --> J
    J --> K[Reasons + recommendations + static reports]
```

## Trust boundaries

Input inventory is an operator statement, not remote attestation. A forged inventory can produce
incorrect conclusions. The tool records that origin and its input hash; hashes prove file identity,
not authenticity. Headers and Docker tags never become version-confirmation evidence.

The offline vendor-fix field is explicitly an operator attestation, not a fetched/signed advisory.
Both CVE IDs and a reviewed HTTPS reference are required. `unsupported` can override the display
status while `cve_assessment` retains the incident-specific interpretation.

HTML escapes untrusted fields. The CLI escapes control characters in asset names. Configuration
exports only an allowlist and does not evaluate PHP expressions. Inputs are size-limited; duplicate
IDs and empty inventories fail rather than generating a misleading empty clean report.

## Reproduce and explain in an interview

1. Run the synthetic inventory and inspect `lab-vendor` versus `lab-web-a`.
2. Explain why a package version below the upstream threshold can still contain a backport.
3. Show that an old header alone remains unknown.
4. Inspect a fixed version's reasons: it does not claim the application is secure.
5. Run the HTML-escaping and branch-boundary tests.

No PHP web application is started. There is no exploit trigger, live scanner, Docker socket mount,
automatic upgrade, external telemetry or hosted UI. Production inventories remain local.
