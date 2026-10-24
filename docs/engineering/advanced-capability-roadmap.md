# ARTEMIS Advanced Capability Roadmap

## Delivery rules

- Build vertical slices that can be tested end-to-end.
- Each slice must have an owner module, schema/version plan, acceptance tests, security review and rollback strategy.
- No feature is considered implemented merely because its documentation, CLI flag, data structure or UI placeholder exists.
- Prefer deterministic controls over LLM judgment for scope, validation, deduplication and lifecycle transitions.

## Roadmap

| Priority | Workstream | Dependencies | Acceptance evidence | Status |
|---|---|---|---|---|
| P0 | Durable state schema, provenance, claims, asset anchors, graph validation | Existing blackboard | Migration preserves legacy records; corrupt state fails closed; invalid status/reference tests | In progress; first slice implemented |
| P0 | Scope enforcement hardening, path boundary checks, DNS rebinding strategy, redirect validation | Policy and HTTP client | Local test cases for host/path/method/redirect/DNS edge cases; no request outside scope | Path boundary and connection-time DNS pinning implemented; IPv6/HTTPS edge validation and redirect regression coverage remain |
| P0 | Evidence redaction, retention and integrity model | Evidence store and report | Secrets test corpus, permissions test, retention/delete test, integrity verification | Planned |
| P1 | Explicit assessment lifecycle and resumable task state | State schema | Crash/restart fixture proves no duplicate completed request and revalidates policy | Planned |
| P1 | Idempotent scheduler, leases and cancellation | Transactional store decision | Concurrent claim tests, lease expiry, cancellation propagation and recovery tests | Planned |
| P1 | Independent finding verification and retesting | Claims, evidence IDs, scenario runner | Labeled positive/negative fixtures; verifier never marks verified without required evidence | Planned |
| P1 | Asset graph persistence and relationship normalization | Asset identity and scope model | Deduplication, scope boundary, historical sightings, cross-run isolation tests | Basic in-run asset node only |
| P1 | Trace retrieval and reusable observations | Trace model and redaction | Search filters, exclude-current-intent, evidence link and redaction tests | Basic local trace store implemented |
| P2 | Information-value ranking and adaptive stopping | Evaluation corpus, stable task model | Ablation shows measurable gain over priority-only baseline without higher unsafe-action rate | Planned |
| P2 | SAST/SCA/SBOM adapter framework | Tool contract and sandbox | Adapter contract tests, timeout/output caps, sample SARIF and SBOM fixtures | SARIF import only |
| P2 | MCP/skill integration registry | Tool permission model | Schema validation, version pinning, explicit grants, audit trail, untrusted output handling | Planned |
| P2 | Approval queue and exact-action approvals | API/auth model, durable tasks | Expired/stale/parameter-mismatch approvals rejected; rejection and resume audited | Planned |
| P2 | API and operator dashboard | Stable backend schema, authentication | UI is backend-backed, authorization tests, no fabricated metrics | Planned |
| P3 | Distributed workers and isolated runtime | Durable scheduler, sandbox design | Fault injection, resource-limit enforcement, cancellation, cleanup, no scope bypass | Planned |
| P3 | Comparative benchmark and ablation harness | Labeled fixtures and repeatable runs | Precision/recall, false positives, evidence completeness, latency, cost, recovery metrics | Planned |

## First implementation slice delivered

- Blackboard schema 2.0 with backward-compatible migration of existing facts/intents/todos.
- Atomic state writes with restrictive permissions and fail-closed handling of malformed JSON.
- Evidence/provenance fields, explicit claim statuses, claim history and graph consistency validation.
- Basic in-run asset records and deduplicated sightings.
- Trace records with query filtering and current-intent exclusion.
- Todo dependency validation and state-transition validation.
- URL path-prefix boundary matching fix.
- Engine integration: baseline observations, planner decisions and registered test results are added to the trace; findings enter the claim lifecycle as `pending_verification`.

## Next slice

Harden destination enforcement and evidence handling before introducing parallel workers. The current HTTP client validates a URL before `requests` performs its own DNS lookup; a production-grade design must close the DNS rebinding/time-of-check-to-time-of-use gap, handle IPv4/IPv6 consistently, and prove redirects cannot escape scope. Stale JSON writers now fail closed under an advisory lock/revision guard, but this is not a transactional merge model. Add persistent task lifecycle and recovery semantics using a transactional backend before concurrent scheduling.
