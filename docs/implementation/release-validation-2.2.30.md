# ARTEMIS 2.2.30 release validation record

**Date:** 2026-10-24  
**Source:** clean extraction of the 2.2.29 release archive with additive 2.2.30 changes. No Git metadata was present, so no Git status/diff or commit provenance can be reported.  
**Safety scope:** all tests are local; no public or production target was scanned; no host firewall rules were applied.

| Gate / test class | Exact command | Result | Interpretation |
|---|---|---|---|
| Compilation | `python -m compileall -q appsec_agent tests agent.py artemis.py scripts/real-runtime-preflight.py` | exit 0 | Syntax/bytecode compilation passed |
| Version | `python artemis.py --version` | exit 0; `ARTEMIS 2.2.30` | Package version matches release |
| Catalog | `python artemis.py --validate-catalog` | exit 0; valid, 12 runnable test IDs, 4 framework mappings | Catalog validation passed |
| Offline dry run | `python artemis.py --policy policy.example.json --dry-run --provider offline > /tmp/artemis-230-dry-run.json` plus JSON assertion `network_requests == 0` | exit 0; 0 network requests | Offline-only smoke test passed |
| Full suite | `python -m pytest -q --disable-warnings --maxfail=1` | exit 0; 214 passed, 3 skipped, 11 subtests passed | Local suite passed; skips are real-container tests and are not passes |
| Unit suite | `python -m pytest -q tests --ignore=tests/integration --disable-warnings` | exit 0; 214 passed, 11 subtests passed | Unit/fake and deterministic local tests passed |
| Fake runtime + dispatcher | `python -m pytest -q tests/test_worker_supervisor.py tests/test_dispatcher.py --disable-warnings` | exit 0; 19 passed | Fake-runtime evidence only |
| Real-container suite | `python -m pytest -q -rs tests/integration/test_container_runtime.py --disable-warnings` | exit 0; 3 skipped | **Not run**: no Docker/Podman and opt-in fixture image unavailable |
| Egress helper tests | `python -m pytest -q tests/test_egress_firewall.py tests/test_scoped_egress.py --disable-warnings` | exit 0; 12 passed | Rule generation and scoped broker unit tests only; no host enforcement proven |
| Auth/store/evidence integration tests | `python -m pytest -q tests/test_dispatcher.py tests/test_authorization.py tests/test_runtime_store.py tests/test_evidence_lifecycle.py --disable-warnings` | exit 0; 75 passed | In-process/fake test evidence; not a live worker-to-queue path |
| Strict host preflight | `python scripts/real-runtime-preflight.py --require-runtime` | exit 2 (expected on this host) | Runtime, namespace, firewall prerequisites unavailable; `nuclei`, `zap`, and `trivy` executables also absent. See `host-preflight-2026-10-24.json` |

## Release blockers retained

- `ART-RUNTIME-013/014` and `ART-ISOLATION-001` remain `IN_PROGRESS`: opt-in tests exist but were not run against a real container runtime.
- `ART-ISOLATION-002` remains `IN_PROGRESS`: no `nft` and network namespace creation fails with `Operation not permitted`; no broker-only route or host default-deny rules were verified.
- `ART-AUTH-001` remains `IN_PROGRESS`: the queue dispatch path does not reach an authorized handler in a real worker; network-required actions fail closed until the boundary is configured.
- `ART-AUTH-004b` remains `IN_PROGRESS`: local hostile-content fixtures do not establish live hosted-provider or end-to-end queue coverage.
- `ART-INT-002/003` and `ART-TRAFFIC-002` remain `IN_PROGRESS`: scanner and MCP/skill transports are not enabled in a real isolated worker, and forced traffic capture is not connected.
- `ART-VERIFY-003` and `ART-BENCH-002` remain `IN_PROGRESS`: no general independent SARIF/workflow verifiers or measured real-scanner baseline are claimed.
- `ART-LICENSE-001` remains `IN_PROGRESS`: technical inventory is recorded; source comparison and qualified human/legal review remain outstanding.

The 95-row register therefore remains 83 `VERIFIED` and 12 `IN_PROGRESS`. This is not a production-readiness score.
