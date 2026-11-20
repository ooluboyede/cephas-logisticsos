# Engineering Roadmap and Acceptance Gates

All gates are sequential. A gate is not accepted merely because code exists; evidence, tests and review are required.

| Gate | Scope | Acceptance evidence |
|---|---|---|
| 0.1 | Repository and engineering foundation | CI, package build, tests, architecture and security baseline |
| 0.2 | CEPHAS ML foundation | tenant-safe data contracts, reproducible pipeline interfaces, integrity tests |
| 0.3 | Feature engineering foundation | versioned feature contracts, validation, lineage and leakage tests |
| 0.4 | Security foundation | server-verified context, database isolation design and negative tests |
| 0.5 | Shipment intelligence | baseline ETA/delay service, evaluation protocol and explainability |
| 0.6 | Fleet and route intelligence | validated domain schemas, feature sets and model evaluation |
| 0.7 | Enterprise integrations | adapter contracts, EDI mapping, API security and contract tests |
| 0.8 | Command centre | role-scoped dashboards, alerts, audit and operational workflows |
| 0.9 | Independent security review | independent findings, remediation and signed acceptance decision |
| 1.0 | Release candidate | deployment guide, SBOM, licence validation, backup/recovery and PoV evidence |

## Release policy

- No gate skips without a documented architecture decision and explicit approval.
- Failed CI blocks progression.
- Security-critical changes require focused review.
- Production deployment requires customer approval and an independent security assessment.
- UPS and FedEx are separate customer deployments with separate tenant data, licences, configuration and credentials.
