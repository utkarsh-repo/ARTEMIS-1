# ARTEMIS Requirements Register

| ID | Requirement | Status | Evidence / acceptance criteria |
|---|---|---|---|
| ART-STATE-001 | Preserve existing facts/intents/todos during schema migration | Implemented | `Blackboard` migrates legacy state and test verifies legacy fact survives |
| ART-STATE-002 | Corrupted state must not be silently replaced | Implemented | Invalid JSON raises `ValueError`; original file remains intact |
| ART-STATE-003 | State writes must be atomic and restrictive | Implemented | Temporary file, mode 0600, fsync where supported, advisory file lock, and revision guard; stale writers fail closed. Concurrent mutations are not merged. |
| ART-KNOW-001 | Claims have explicit verification states and provenance | Implemented (local record model) | Claim lifecycle statuses and status history; verified state requires reviewer/verifier and evidence IDs; this model does not itself independently verify vulnerability impact |
| ART-KNOW-002 | Claims link to supporting facts and evidence | Implemented (record-level) | Graph edges and reference validation; broad evidence lineage still evolving |
| ART-GRAPH-001 | Validate graph edges and references | Implemented (basic) | `validate_graph()` reports dangling/unsupported edges and missing claim references |
| ART-ASSET-001 | Represent in-scope application as an asset node | Partial | Target asset is recorded per run; global normalized cross-run asset graph is not implemented |
| ART-TRACE-001 | Persist structured execution traces and search prior observations | Partial | Per-run trace storage/search added; no cross-worker or cross-assessment retrieval yet |
| ART-POLICY-001 | Path prefix must match path boundary and reject nested encoded traversal | Implemented | `/api` permits `/api/users`, rejects `/apix/users`; double-encoded traversal fixtures are blocked |
| ART-VERIFY-001 | Scanner/check findings must not be marked verified automatically | Implemented (candidate classification) | Engine records findings as `pending_verification`; independent verifier is planned |
| ART-PLAN-001 | Dynamic bounded planning selects registered tests only | Partial | Existing planner constraint remains; no measured information-gain ranking |
| ART-RUNTIME-001 | Durable concurrent scheduler with leases and cancellation | Missing | Requires transactional persistence and worker lifecycle implementation |
| ART-APPROVAL-001 | Exact-action human approval queue | Missing | Requires approval records bound to target/parameters/policy version/expiry |
| ART-UI-001 | Backend-backed operator interface | Missing | No frontend/API in uploaded archive |
| ART-BENCH-001 | Reproducible accuracy and cost benchmarks | Missing | Quality plan added; labeled corpus and benchmark runner required |

Update this register in the same change that implements a requirement. Do not mark a requirement implemented based solely on documentation or a placeholder interface.

| ART-COV-001 | Do not count deferred/failed tests as executed coverage | Implemented | Engine persists per-test statuses; coverage/report integration test verifies missing OpenAPI input is `deferred`, not completed or executed |
| ART-REPORT-001 | Report claim uncertainty and unresolved questions | Implemented (local report) | Markdown report reads persisted claim records and lists unresolved claim states; no claim is auto-verified |

| ART-EVIDENCE-002 | Redact sensitive evidence before persistence and model exposure | Implemented with limitations | Common secret headers/fields, URL query values, JSON bodies, and bearer/JWT-like strings are redacted; binary body bytes are omitted. Redaction is not exhaustive for arbitrary proprietary formats. |
| ART-EVIDENCE-003 | Evidence writes must not follow caller-controlled paths or symlinks | Implemented where supported | Evidence filenames must be basenames; `O_NOFOLLOW` is used where available; files are mode 0600 and writes are fsynced. |
| ART-POLICY-002 | Reject malformed or ambiguous URL and allowlist inputs | Implemented for covered cases | Regression tests cover malformed ports, fragments, control characters, backslashes, trailing-dot/wildcard host entries, and malformed policy lists. |
| ART-POLICY-003 | Bind outbound HTTP(S) connections to policy-validated DNS results | Implemented with platform-validation caveat | Custom urllib3 connection classes dial a validated IP while preserving the requested hostname for Host/TLS checks; adapter rejects proxies; a simulated DNS-rebinding regression test confirms a newly private address is blocked. Add IPv6 and HTTPS/SNI integration coverage before production use. |
| ART-STATE-004 | Prevent stale blackboard instances from silently overwriting newer state | Implemented for local file backend | Advisory file lock serializes save checks; optimistic revision mismatch raises `ConcurrentStateWriteError`; regression test confirms newer facts remain intact. Callers must reload/reconcile after conflict. |


## Runtime queue implementation (2.2.2)

| ID | Requirement | Status | Evidence / acceptance criteria |
|---|---|---|---|
| ART-RUNTIME-001 | Transactional job/task persistence | VERIFIED | SQLite `BEGIN IMMEDIATE`, foreign keys, schema version, restrictive database permissions; `tests/test_runtime_store.py` |
| ART-RUNTIME-002 | Idempotent job creation bound to policy digest | VERIFIED | Same key and digest reuses job; different digest rejected |
| ART-RUNTIME-003 | Dependency-aware task creation and cycle rejection | VERIFIED | Dependencies gate claims; cycles rejected atomically; failed prerequisite blocks dependent task |
| ART-RUNTIME-004 | Exclusive worker leases and lease-token authorization | VERIFIED | Two-thread claim test yields exactly one winner; stale/wrong token rejected |
| ART-RUNTIME-005 | Heartbeats, bounded retries, expired lease recovery and cancellation | VERIFIED | Runtime tests exercise heartbeat, retry cap, lease recovery, and kill-switch state transitions |
| ART-RUNTIME-006 | Lifecycle event audit and runtime CLI | VERIFIED | Events are queryable; CLI smoke created job, added task, and retrieved status |

Limitations: SQLite is a single-host queue, not a distributed multi-host scheduler. No worker process/container is launched or killed by this queue yet. A policy digest is stored but the queue does not independently load and authorize the policy before dispatch. See `docs/implementation/requirements-register.md` for granular acceptance criteria and open work.

| ART-AUTH-001a | Canonical policy digest calculated from validated policy and checked at task claim | VERIFIED | Runtime tests verify canonical ordering and policy mismatch; CLI subprocess test creates and claims with the same validated policy file |
