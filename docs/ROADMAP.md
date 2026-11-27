# Engineering Roadmap and Acceptance Gates

All gates are sequential. A gate is not accepted merely because code exists; evidence, tests and review are required.

| Gate | Scope | Acceptance evidence |
|---|---|---|
| 0.1 | Repository and engineering foundation | CI, package build, tests, architecture and security baseline; 0.1.2 runtime isolation prerequisite below |
| 0.2 | CEPHAS ML foundation | tenant-safe data contracts, reproducible pipeline interfaces, integrity tests |
| 0.3 | Feature engineering foundation | versioned feature contracts, validation, lineage and leakage tests |
| 0.4 | Advanced security hardening and isolation revalidation | cryptographic model trust, audit integrity, secrets, licensing, deployment hardening, and revalidation of 0.1.2 controls |
| 0.5 | Shipment intelligence | baseline ETA/delay service, evaluation protocol and explainability |
| 0.6 | Fleet and route intelligence | validated domain schemas, feature sets and model evaluation |
| 0.7 | Enterprise integrations | adapter contracts, EDI mapping, API security and contract tests |
| 0.8 | Command centre | role-scoped dashboards, alerts, audit and operational workflows |
| 0.9 | Independent security review | independent findings, remediation and signed acceptance decision |
| 1.0 | Release candidate | deployment guide, SBOM, licence validation, backup/recovery and PoV evidence |

## Gate 0.1.2 mandatory runtime prerequisite

Owner-approved reconciliation: PR #12 comments 7213516377 (gate mapping and freshness) and 7213837102 (controlled T-02.2 implementation authorization). No renumbering or skipped gates.

Preserve R-26. Before Gate 0.1.2 acceptance, require T-02 real PostgreSQL isolation; T-03 identity and membership; T-04 broker/transaction/pool; T-05 centralized authorization; T-06 jobs; T-07 exports/cache/storage; T-08 adversarial tests; T-09 governance; T-10 independent consolidated exact-commit acceptance. Gate 0.1.3 remains blocked until acceptance. Gate 0.4 retains broader hardening and revalidation; it cannot replace foundational isolation.

The 30-second model limits authorization decision age at protected SQL dispatch and COMMIT initiation, not physical completion or instantaneous revocation. T-02.1B architecture accepted with conditions, not implementation acceptance. See T02_IMPLEMENTATION_ACCEPTANCE.md. No production authorization.

## Release policy

- No gate skips without a documented architecture decision and explicit approval.
- Failed CI blocks progression.
- Security-critical changes require a genuinely independent qualified security reviewer on the final exact head, with recorded decision and required GitHub approval; one generic ruleset approval alone does not establish reviewer independence.
- Production deployment requires customer approval and an independent security assessment.
- UPS and FedEx are separate customer deployments with separate tenant data, licences, configuration and credentials.
