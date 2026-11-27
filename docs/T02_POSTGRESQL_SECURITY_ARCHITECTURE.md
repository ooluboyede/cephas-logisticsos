# T-02 — PostgreSQL tenant isolation architecture

Status: proposed, documentation only; implementation and independent acceptance pending.
Baseline: R-26 0522c53560b4082b08a0fb379ca50f137253c054 (PR #11). Gate 0.1.2 remains unaccepted.

## Baseline and scope
The inspected architecture, security baseline, package metadata, composition root and tenant contracts establish a modular monolith, opaque identifiers, trusted adapter interfaces and a bounded static scanner. No production database implementation is established by this evidence. Main-to-baseline comparison reports 145 commits ahead, zero behind and 16 changed files; it is not a complete tree inventory. Preserve the accepted stack and do not merge without explicit authorization. The original roadmap places security foundation at Gate 0.4; T-02 is proposed prerequisite work for the broader Gate 0.1.2 acceptance, subject to explicit governance reconciliation before implementation.

## Decisions proposed
- PostgreSQL 16 or 17, Psycopg 3, versioned SQL migrations; supported versions verified in real database CI.
- Preserve opaque case-sensitive 1–128 character identifiers and existing validation semantics; use text with explicit constraints and deterministic collation, not implicit UUID conversion.
- Tenant registry and business-unit registry with composite tenant/business-unit keys. Every scoped operational row carries both identifiers; composite foreign keys include scope to prevent cross-scope references.
- Separate non-login owner, migration identity, restricted runtime identity and narrowly scoped membership lookup identity. Runtime must not own tables, inherit owner privileges, have BYPASSRLS, superuser, role administration, TRUNCATE or DDL privileges. No broad PUBLIC grants. Administrative roles remain outside the runtime threat boundary.
- Enable and FORCE RLS on scoped tables. Explicit SELECT, INSERT, UPDATE, DELETE policies with USING and WITH CHECK as applicable; no permissive broad policy. Missing, empty or malformed context denies access. Scope changes through UPDATE are forbidden.
- Bind subject, tenant and business unit only from trusted adapter output, in an explicit transaction using parameterized transaction-local settings. Never derive context from raw request fields. No session-level scope or autocommit data access. Rollback on failure, reset/verify pooled connections before reuse, discard connections on cleanup failure.
- Custom PostgreSQL settings are not unforgeable credentials: the runtime SQL identity can change them. RLS with these settings protects against omitted filters and accidental scope mistakes, not arbitrary SQL execution or compromised runtime identity. Restrict SQL execution to reviewed parameterized repository operations; no user SQL, no raw connection exposure. Evaluate stronger database-authenticated scope binding before claiming resistance to compromised runtime SQL.
- Membership lookup must be server-authoritative, restricted and separately authorized; no circular dependency on an unverified tenant scope. T-03 defines identity validation and membership revocation semantics; T-04 implements transaction/pool boundary. T-02 test harness must not be presented as production authentication.
- No SECURITY DEFINER functions by default; any exception requires explicit grants, fixed safe search_path, qualified objects and independent review. Avoid owner-executed views bypassing RLS; test effective runtime privileges and policy catalog.
- Customer-controlled deployment, offline signed licensing separate from authorization. No customer credentials or live carrier integration.

## Implementation sequence
1. Review this architecture and reconcile gate scope; complete inventory and branch-protection evidence.
2. Add migrations for roles, schemas, tenant and business-unit keys and a minimal scoped test entity; no carrier domain expansion.
3. Add real PostgreSQL integration harness with distinct migration/runtime identities; test clean installation and upgrade behavior.
4. Implement and test policies and privilege boundaries. Keep runtime transaction binding provisional until T-04.
5. Run existing scanner, lint, format, types, unit and real database integration tests in one validated CI cycle. Integration tests must fail, not silently skip, when required database is unavailable.
6. Independent exact-commit review; no merge or Gate 0.1.2 acceptance implied.

## Acceptance matrix
- Valid scope: allowed CRUD within tenant and business unit.
- Different tenant and same-tenant different unit: reads invisible; inserts and scope-changing updates rejected; update/delete cannot affect foreign rows.
- Missing/empty/malformed scope: no data access; writes rejected.
- Composite FK rejects cross-scope references; test uniqueness and error leakage boundaries.
- Runtime cannot disable RLS, alter policy, assume owner, truncate, or bypass through inherited roles; verify catalog and effective privileges.
- Transaction rollback, commit, pool reuse and concurrent requests: no residual scope; full pool tests in T-04.
- Test membership revocation and unauthorized identity in T-03/T-05; background jobs, exports, caches and object storage remain separate work packages.
- Document residual risks including privileged DB administrators, arbitrary runtime SQL, side channels and deployment misconfiguration.

## Governance
Architecture only. No runtime implementation, production certification, branch protection verification, Maersk authorization or full repository inventory is claimed. PR #11 and prior stack remain unmerged unless separately authorized. R-26 acceptance is limited to reviewed scanner regression scope.
