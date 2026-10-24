# ARTEMIS Development Progress

## 2026-10-24: Initial audit and foundational state slice

### Baseline
- Uploaded archive inspected; project is a Python CLI with JSON/JSONL persistence.
- Baseline `python -m pytest -q`: 12 passed.
- Upstream reference review: public READMEs, license files, Cairn dispatcher/server protocol specs, selected Cairn tests and selected ARTEX planner/worker/finding/traffic-capture source were inspected.

### Implemented
- Blackboard schema 2.0 with migration defaults for legacy records.
- Fail-closed loading for malformed blackboard JSON.
- Atomic state writes, restrictive file modes and fsync where supported.
- First-class claim records with explicit status, provenance, evidence references, confidence rationale, limitations, version and status history. Verified status cannot be assigned at creation and requires a reviewer/verifier plus evidence IDs.
- Basic asset nodes with scope status and deduplicated sightings.
- Structured traces and bounded query filtering with current-intent exclusion.
- Todo dependency validation and state-transition validation.
- Basic graph integrity validation, duplicate-node/reference/status checks, and refusal to downgrade state files from a newer schema.
- Per-test lifecycle statuses now distinguish executed, failed, blocked, deferred, cancelled, stale and review-only checks. Deferred configuration is not added to successful `completed_tests`.
- Coverage and Markdown reports expose partial execution, deferred checks, claim states and unresolved questions. Raw response bodies are excluded from test trace summaries.
- Engine records baseline observations, planner decisions and registered test results as traces.
- Engine creates `pending_verification` claims for findings; it does not equate a scanner/check output with a verified vulnerability.
- Path-prefix boundary matching and nested URL-encoding traversal fix (`/api` no longer matches `/apix`; double-encoded traversal is rejected).
- Initial current-state, target-state, parity matrix, roadmap, threat model, quality plan and requirements register documents.

### Validation after changes
- `python -m pytest -q`: 26 passed (including local HTTP end-to-end integration and 3 path-encoding subcases).
- `python -m compileall -q .`: passed.
- `python artemis.py --version`: passed.
- `python artemis.py --validate-catalog`: passed (12 runnable tests, 4 framework maps).
- `python artemis.py --validate-state <path>`: valid graph check passed; missing path correctly exits non-zero.
- Packaged release ZIP was extracted to a clean directory and re-tested: 26 tests passed; version and catalog validation passed.
- `python artemis.py --policy policy.example.json --dry-run --provider offline`: passed and reported `network_requests: 0`.

- Static linters (`ruff`, `pyflakes`) are not installed in the execution environment. `pip check` reports an unrelated pre-existing global environment conflict (`moviepy` requires Pillow below 12, while Pillow 12.3.0 is installed); ARTEMIS declares only `requests` as a runtime dependency.

### Known limitations
- No independent verifier, persistent distributed scheduler, worker pool, approval gateway, frontend, MCP registry or scanner execution adapters yet.
- DNS check is not bound to the actual HTTP socket connection, so DNS rebinding hardening remains open.
- Current state backend remains local JSON. Stale concurrent writers are blocked, but changes are not merged and a transactional backend is still required for a real concurrent worker scheduler.
- Full upstream file-by-file and issue/commit audit remains open; this matrix is a source-backed working inventory, not a claim of exhaustive review.

### Next priority
Harden network destination validation and evidence handling, then implement resumable task lifecycle with an explicit transactional persistence decision before adding parallel workers.


## 2026-10-24: Micro-level evidence and policy hardening (2.2.1)

### Implemented
- Evidence records redact sensitive request/response headers, common secret-bearing structured fields, bearer tokens/JWT-like values, and credential-like query parameters before persistence.
- Model-safe observations redact URL query secrets and parse JSON excerpts for nested key-aware redaction.
- Evidence body storage records the original response SHA-256 separately from the stored representation SHA-256; binary response bodies are omitted rather than persisted as raw base64.
- Evidence append rejects non-basename filenames, refuses symlink destinations where `O_NOFOLLOW` is supported, enforces mode 0600, and fsyncs writes.
- Policy validation rejects malformed/non-list allowlists and methods, trailing-dot/wildcard/whitespace host entries, invalid ports, URL fragments, control characters, malformed URLs, and ambiguous backslashes.
- HTTP(S) connections now dial a freshly resolved and policy-checked IP while retaining the original hostname for Host and TLS verification. Proxy routing is rejected by the adapter to avoid bypassing destination pinning. A regression test simulates DNS changing from a public address during preflight to a private address at connection time and confirms the request is blocked.
- HTTP responses are explicitly closed after bounded body capture, including when the configured response cap is reached.
- Blackboard writes now use an advisory file lock and optimistic revision check; a stale writer raises `ConcurrentStateWriteError` instead of silently replacing newer persisted state. Opening an unchanged current-schema board no longer increments its revision. This prevents silent lost updates but does not merge concurrent changes or replace a transactional database.
- Added regression tests for nested JSON secrets, query-string credentials, evidence symlink protection, path traversal in evidence filenames, malformed policy values, and malformed URLs.

### Validation
- `python -m pytest -q`: 36 passed, 7 subtests passed.
- `python -m compileall -q .`: passed.
- `python artemis.py --version`: 2.2.1.
- `python artemis.py --validate-catalog`: passed (12 runnable tests, 4 framework maps).
- Offline dry-run: passed with `network_requests: 0`.

### Remaining caveats
- Redaction is defense-in-depth, not a guarantee that every proprietary token format or sensitive data type is recognized. Keep raw production evidence out of shared artifacts and validate the redaction policy against your application's real response schemas.
- Destination pinning is covered by local regression tests, but should receive additional IPv6, HTTPS certificate/SNI, multi-address failover, and supported-platform testing before production use.
- JSON persistence remains single-process only; multi-worker scheduling must wait for transactional storage and lease semantics.


## 2026-10-24: Transactional runtime queue slice (2.2.2)

### Reference-source audit performed
- Retrieved Cairn README, `docs/specs/dispatcher-design.md`, and `docs/specs/server-protocol.md` through the connected GitHub source interface. Confirmed the dispatcher is the control/protocol writer; worker tasks include bootstrap/reason/explore; lease/heartbeat, cancellation and project-state semantics matter.
- Retrieved ARTEX README and selected planner, worker, finding workflow, capture, database, orchestration/server and UI type sources. Confirmed separate asset/exploration graphs, task dependencies, persisted activity traces, finding/traffic linkage, interception/approval, PostgreSQL persistence and operator UI are distinct capabilities.
- Direct `git ls-remote` from the execution container failed because GitHub DNS/network access was unavailable. This is not a full recursive upstream audit; remaining source inventory is explicitly tracked. No upstream source code copied.

### Implemented
- Added `appsec_agent/runtime_store.py`, using standard-library SQLite transactions and schema versioning for jobs, tasks, dependency edges and ordered lifecycle events.
- Added canonical policy digest calculation from the validated policy object; CLI job creation computes it from `load_policy()`, and claim time recomputes it and rejects a mismatched job digest. An optional `--policy-digest` is only an assertion and cannot override the computed digest. Idempotent job creation is bound to that digest; conflicting digest reuse fails closed.
- Added task validation, per-job idempotency keys, dependency existence checks and cycle detection with transaction rollback.
- Added exclusive task claims with worker IDs and random lease tokens; only the current unexpired token can start, heartbeat, complete or fail a task.
- Added bounded retry attempts, expired lease recovery, terminal failure handling, and propagation of failed prerequisites to `blocked` dependent tasks.
- Added job cancellation that cancels pending/leased/running tasks and invalidates leases. Added lifecycle event query and job/task status reads.
- Added common-secret redaction for persisted job metadata, task input and result objects; rejects symlink database paths and sets database/WAL/SHM modes to 0600 where present.
- Added canonical policy digest calculation from the validated policy object. CLI job creation computes it from `load_policy()`, claim time recomputes it and rejects mismatches; `--policy-digest` is an optional assertion, not an override. Added a regression test proving digest stability under key reordering and change under policy mutation.
- Exposed runtime queue operations through `agent.py` `--runtime-action` CLI commands. These commands manipulate the queue only; they do not launch scanners or execute target requests.
- Added `docs/implementation/requirements-register.md` and `docs/implementation/capability-parity-matrix.md` with individually testable requirements and reference inventory. Existing engineering docs updated to link runtime capabilities and limitations.

### Validation
- `python -m pytest -q`: **54 passed, 7 subtests passed**.
- `python -m compileall -q .`: passed.
- `python artemis.py --version`: `ARTEMIS 2.2.2`.
- CLI integration test and smoke: created SQLite job, added task, claimed it with the matching canonical policy digest, and read back persisted job/task/lease state across separate CLI invocations.
- Runtime tests cover canonical policy digest stability/change detection, claim-time digest mismatch, idempotency/policy digest mismatch, dependency ordering and cycles, blocked descendants, wrong/stale lease tokens, retries, expiry recovery through both recovery and claim paths, cancellation, concurrent claim winner, permissions, symlink rejection, secret redaction, event ordering, and CLI create/add/claim/status persistence across subprocesses and rejection of a forged digest override.

### Known defects / limitations
- Runtime task queue is not yet wired to the existing assessment engine's planning/execution loop. No task handler is invoked from `claim_next`; this is deliberate until execution authorization and worker isolation are ready.
- CLI computes and checks the canonical digest, but lower-level `RuntimeStore` methods are trusted internal APIs and do not load a policy file themselves. No worker action executor is wired yet, so action-time scope revalidation is still required.
- SQLite is single-host; no PostgreSQL backend or distributed scheduler.
- Expiry recovery does not terminate OS processes because no supervised worker process exists. Lease timeout is not a substitute for process time/resource limits.
- JSON blackboard and SQLite runtime records are separate stores; task completion is not yet reconciled with persisted evidence or blackboard facts.
- No authenticated HTTP API, operator UI, approval gateway, independent finding verifier, scanner adapters, or benchmark corpus yet.
- Upstream source review remains partial, and license compatibility/use restrictions require legal review before any code reuse or distribution claim.

### Exact next requirements
1. `ART-AUTH-002` and `ART-AUTH-003`: exact-action approval records and fixed-schema tool allowlist.
2. `ART-RUNTIME-013` / `ART-ISOLATION-001`: supervised isolated worker with wall-clock/resource limits and deterministic kill.
3. `ART-AUTH-001`: revalidate scope/policy immediately before each actual outbound action when the worker runner is connected.
4. `ART-PLAN-005`: reconcile task result, blackboard facts and evidence on restart.
5. `ART-VERIFY-001`: independent finding verifier and positive/negative fixtures.
