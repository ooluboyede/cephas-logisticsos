# CEPHAS LogisticsOS

**AI-powered global logistics intelligence and operations platform.**

CEPHAS LogisticsOS is a modular enterprise software platform designed for customer-controlled deployment and annual signed licensing. Its engineering foundation is CEPHAS ML, deterministic and reproducible feature engineering, and the CEPHAS security architecture.

## Product objectives

- Predictive shipment ETA, delay and exception intelligence.
- Fleet, route, hub, warehouse and last-mile analytics.
- Customs and cross-border workflow intelligence.
- Enterprise integrations through approved APIs, event streams and EDI.
- Customer-controlled deployment, data custody and licensing.
- Explainable, monitored ML with tenant-safe data and model boundaries.

## Non-negotiable engineering principles

1. Database-enforced tenant and business-unit isolation; application checks alone are insufficient.
2. Server-verified tenant context, fail-closed authorization and PostgreSQL RLS where applicable.
3. No cross-tenant training, feature materialization, evaluation or inference data leakage.
4. No untrusted model deserialization. Verify publisher signature and artifact integrity before loading.
5. Reproducible feature definitions, point-in-time correctness, lineage and leakage controls.
6. Secrets and signing private keys are never committed to source control.
7. CI security checks are release gates; no bypassing failed checks.
8. Customer operational data remains in the customer's approved environment.
9. Implemented, planned and experimental capabilities must be explicitly distinguished.
10. Production readiness requires independent security review and customer acceptance.

## Current status

**Foundation only — not production-ready and not yet validated for customer deployment.**

This initial repository baseline establishes architecture, engineering controls and a minimal Python package skeleton. It does not claim completed UPS/FedEx integrations, trained logistics models, certified connectors or production security certification.

## Repository layout

```
src/cephas_logisticsos/
  api/                 # API boundary and request context
  core/                # shared configuration and domain primitives
  features/            # feature contracts and validation
  ml/                  # model and training contracts
  security/            # authorization and trust boundaries
  tenancy/             # tenant and business-unit context
tests/
docs/
.github/workflows/
```

## Development

Requires Python 3.11 or newer.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
ruff check .
```

## Architecture and delivery gates

See [Architecture](docs/ARCHITECTURE.md), [Security baseline](docs/SECURITY_BASELINE.md), [ML and feature engineering](docs/ML_FEATURE_ENGINEERING.md), and [Roadmap](docs/ROADMAP.md).

## Licensing

Commercial licensing, edition controls, customer deployment limits and renewal validation will be implemented under the CEPHAS licensing authority. No signing keys or production licence secrets belong in this repository.

## Security reporting

Do not disclose vulnerabilities publicly. Follow the private reporting process established by the repository owner. Until a formal security contact is published, report issues privately to the repository administrators.

---
**CEPHAS AI Solutions — Enterprise AI & Industry Intelligence**
