# ZIM-06.2.3 — OAuth hardening and acceptance preparation

Decision: NOT ACCEPTED for runtime integration. Isolated candidate only.
Tracking issue #10; parent 9123d8b3fc42a684b7f052b1ac900a601568975f.

## Changes
- Recheck the trusted credential provider after token issuance, before cache publication.
  Reject observed in-flight changes and provider errors. Provider must still change the
  revision on rotation, and revocation after the final read is not atomic with use.
- Reject HTTP parser header defects and non-ASCII Content-Length.
- Reject overflowing JSON floats as well as NaN/Infinity literals.

## Local evidence
54 tests passed (7 additional cases), 95.35% statement coverage of the locally mirrored
package sources and test suite, 80% threshold met. Python 3.13.5, pytest 9.0.2,
pytest-cov 7.0.0. Python 3.11 grammar parsing passed; runtime not tested.
No live calls or real credentials. Changed source/test files match tested Git blob hashes.

## Mandatory outstanding acceptance criteria
- [ ] Run full repository CI-equivalent commands on Python 3.11 with declared dev dependencies.
- [ ] Ruff lint, Ruff format, Mypy and pytest/coverage all pass on exact candidate.
- [ ] Enforce cancellation across DNS, connect, TLS and slow header/body reads at a
  bounded wall-clock deadline; no orphan request after timeout. Current phase budget
  rejects late results but cannot interrupt all blocking calls.
- [ ] Enforce customer-controlled network egress and approved trust roots; fixed hostname
  is not a network-level egress policy.
- [ ] Verify carrier contract, approved data use and live sandbox TLS interoperability.
- [ ] Bind credential provider to accepted authenticated tenant/business-unit context;
  prove cache and credential isolation and rotation/revocation behavior.
- [ ] Independent exact-commit security review and documented acceptance.

## Local validation (from exact branch, Python 3.11 environment)
    python -m pip install -e ".[dev]"
    ruff check .
    ruff format --check .
    mypy src
    pytest --cov=cephas_logisticsos --cov-report=term-missing --cov-fail-under=80

Do not wire to runtime, merge, or advance the authentication acceptance gate until
the blocking controls and evidence are resolved. R-25 review remains separate.
