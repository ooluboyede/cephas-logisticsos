# ZIM-06.2.1 — OAuth transport hardening

Status: isolated candidate; no runtime wiring, production access or independent acceptance.

Transport policy: fixed HTTPS host and path, sandbox-only scopes, exact form field
allowlist, standard verified TLS context (TLS 1.2 minimum; 1.3 negotiated where supported),
no redirect following, no proxy or retry, 10-second socket timeout, 64 KiB request and
response limits, identity encoding, JSON-only response, duplicate JSON field and ambiguous
framing checks, sanitized errors. No real secrets or carrier payloads used.

Limits: socket timeout is not a total deadline; DNS and slow streaming may exceed it.
Network/DNS egress isolation, strict end-to-end deadlines, HTTP parser edge cases, live
TLS interoperability, secret-store integration and trusted tenant composition remain
unaccepted. The prior lifecycle module is unchanged; no integration test of the two
modules in this step. No actual HTTPS request was sent.

Local targeted verification: 26 mocked tests passed, 95% statement coverage of
zim_transport.py, Python 3.13.5 / pytest 9.0.2. Python 3.11, Ruff, Mypy, full suite,
independent security review and CI are outstanding. See issue #10 for change control.

Proposed next: close validation gaps and test OAuth lifecycle with mocked transport
end-to-end before starting the read-only tracing adapter.
