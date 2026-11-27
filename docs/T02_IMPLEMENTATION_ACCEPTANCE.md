# T-02.2 — Controlled non-production implementation acceptance contract

Owner authorization: PR #12 comment 7213837102. Independent review LOGISTICSOS-T02-ISR-002 at ed4534d4c68497652767572e2d8d9b71fa1eafa0, recorded in comment 7213810863. Accepted R-26 baseline 0522c53560b4082b08a0fb379ca50f137253c054. This document is a planning and governance deliverable, not evidence of implemented controls.

## Residual-condition register

| ID | Severity | Mandatory delivery and evidence | State |
|---|---|---|---|
| R-01 | High | Serialized controller across database, routing, network and vault; committed-state rechecks, stale activation denial, concurrent retirement and fencing tests | Open |
| R-02 | High | Independent watchdog, actual driver submission and COMMIT-initiation freshness checks; pause, queue, retry and cancellation tests; no hard real-time claim | Open |
| R-03 | Medium | Durable independently verifiable two-human approval evidence bound to exact change_ref, deployment, role and scope | Open |
| R-04 | Medium | Explicit capped customer DBA connection allocation within approved slot classes; positive termination wait plus verified disappearance | Open |
| R-05 | Medium | Non-null unique immutable membership generation, non-resettable monotonic revision, atomic audit and concurrency tests | Open |
| R-06 | Medium | Integration push/PR triggers and actual required-check evidence; T-02.2A proposes filters, not proof of promotion | Proposed |
| R-07 | Medium | Genuine independent qualified review after final push and GitHub approval; designated reviewer enforcement recommended, not configured | Open |
| R-08 | Medium | Roadmap and architecture status reconciliation via governed PR; T-02.2A proposes edits | Proposed |
| R-09 | Low | Real PostgreSQL 16 migrations/tests; mandatory fail-closed check with exact evidence | Open |

## Implementation packages and acceptance sequence

A: governance and CI foundation. B: schema, migrations, scoped logins and role privileges. C: approval-bound registry and lifecycle controller. D: operational RLS and exact catalog manifest. E: membership, freshness and broker controls. F: capacity, fencing, recovery and transaction outcome controls. G: real PostgreSQL 16 adversarial qualification. H: consolidated independent review. Packages are workstreams, not accepted release gates. T-03/T-04 integration dependencies remain mandatory. No implementation claimed by A.

## Reviewer Section 6 A–H obligations

- Preserve R-26 scanner, composition/adapter boundary, tenant context and tests; review any changes separately.
- Use disposable dedicated PG16, version-qualified evidence, direct independent scoped logins and versioned migrations.
- Prove registry expiry, OID mismatch/recreation, uniqueness, immutability, tombstone, retirement, rotation, restore/clone, concurrency across external lifecycle.
- Prove privileges, role graph and options, RLS owner/bypass limitations, default privileges, drift, alternate paths, same IDs across scopes, foreign CRUD/association/upsert and sanitized constraint errors.
- Validate all 120 connection slots and DBA allocation, 100-scope load, skew, exhaustion, stale broker, reconnect denial and split-brain fencing; confirm termination.
- Prove primary membership, generation/revision, revocation, lost notifications, expiration, queue/driver/commit boundaries, cancellation and process pauses; late/lost commit, live original backend, same-ID/different payload and no premature retry.
- Mandatory real PG16 integration job: fails if DB unavailable, never silently skips, records exact SHA/version/checksums/identities/sanitized logs/counts. Add as required protected check before implementation acceptance. Verify actual integration target CI coverage before promotion.
- Reconcile roadmap and status through protected PR. Require qualified independent review and final-head GitHub approval. No self-approval, bypass, or relaxation of ruleset 28220598.

No production migration, credentials, customer data, deployment, Maersk implementation, release certification, gate progression or merge authorized by the implementation decision.
