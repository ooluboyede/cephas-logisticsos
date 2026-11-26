# ZIM-06.2 — isolated sandbox OAuth prototype

Status: prototype, NOT accepted for runtime integration. Parent: main at
70aa07a49c3d3691ef037c6750a32fa2f6c4a64e. Tracking issue #10.
The R-25 review stack is not a dependency of this isolated experiment and is not modified.

Implemented: fixed sandbox product scopes, injected credential provider and transport,
single-binding synchronized token cache, expiry margin and TTL cap, rotation revision
invalidation, stale-token-safe invalidation, bounded token shape, sanitized failures.

Not implemented: live HTTP transport, subscription key handling, trusted tenant resolver,
secret store, audit sink, production configuration, tracing/schedule requests, database
integration or independent security acceptance. Binding equality is not authentication:
the future composition root must supply verified identity and authorized membership.
The credential provider must change revision on rotation. The transport must enforce
TLS/host/path policy, no redirects, response size and timeout limits and redaction.
Never use this prototype directly with live carrier credentials.

Tests are synthetic only. No raw carrier payloads or actual credentials are stored.
Before runtime wiring, confirm API contract, credential lifecycle and permitted data use,
accept the tenant-security baseline, and perform an exact-commit independent review.
