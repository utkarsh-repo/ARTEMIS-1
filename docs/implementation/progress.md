# ARTEMIS implementation progress journal

## Batch 2.2.3 — exact-action approval primitive

**Date:** 2026-10-24  
**Requirements addressed:** `ART-AUTH-002a` through `ART-AUTH-002f`; partial progress on `ART-AUTH-002`.  
**Dependency status:** Runtime SQLite store and canonical policy digest from 2.2.2 are present.

### Files created or modified

- `appsec_agent/approval.py` — action canonicalization/digest, policy-scope revalidation, approval request, independent decision, expiry, atomic one-time consume, list/get.
- `appsec_agent/runtime_store.py` — schema v2 approval ledger and index; stores digest and parameter names, not parameter values.
- `agent.py` — `approval-request`, `approval-decide`, `approval-consume`, and `approval-list` CLI actions; derives operator identity from the current OS account and rejects caller-supplied impersonation.
- `tests/test_approval.py` — digest binding, secret persistence, policy mismatch, self-approval, parameter/target/job/policy mutation, expiry, rejection, replay, concurrency and out-of-scope target tests.
- `docs/implementation/requirements-register.md` — granular subrequirements and status/evidence.
- `docs/implementation/capability-parity-matrix.md` — approval capability update and remaining gaps.
- `README.md`, `CHANGELOG.md`, `appsec_agent/__init__.py` — v2.2.3 docs/version.

### Implemented behavior

- An approval digest binds job ID, exact target string, tool identifier, exact JSON parameter object and policy digest.
- Requests require a policy snapshot whose canonical digest matches the assessment and revalidate URL/method against the existing deterministic scope policy without resolving DNS.
- Sensitive parameter values are not stored in the approval table; only sorted top-level parameter keys and the action digest are stored.
- The requester cannot approve their own request in the gateway primitive.
- Expired requests become `expired`; rejected, expired, pending and consumed approvals cannot be consumed.
- Consumption runs in a transaction and exactly one of two concurrent consumers can succeed.
- Approval lifecycle events are appended to runtime event history.
- CLI actor identity comes from the POSIX UID-to-account mapping (or platform fallback) rather than trusting an arbitrary supplied operator label or `USER` environment variable.

### Validation

- Focused tests: `python -m pytest -q tests/test_approval.py tests/test_runtime_store.py` — **29 passed** after scope validation was added.
- Full regression suite: `python -m pytest -q` — **67 passed, 7 subtests passed**.
- `python -m compileall -q .` — passed.
- `python artemis.py --version` — `ARTEMIS 2.2.3`.
- `python artemis.py --validate-catalog` — valid; 12 runnable tests, 4 framework maps.
- Offline dry run — passed with `network_requests: 0`.
- CLI subprocess smoke — create job, request approval, list approval and reject a spoofed `--operator-id` passed.
- Schema migration regression — version 1 metadata upgrades to version 2 and creates the approval ledger.

### Defects, limits and security notes

- Approval consumption is not yet called by an actual scanner or worker dispatch path. Do not claim end-to-end approval enforcement.
- No authenticated HTTP operator API or role-based authorization exists. OS account binding protects against a simple CLI-supplied identity string but is not a substitute for multi-user authentication/authorization. The runtime DB is private to its creating OS account by default; a second OS account cannot use the CLI approval flow unless shared access is deliberately configured. Do not weaken file permissions casually; this is a deployment blocker for real two-person CLI approvals.
- `resolve_dns=False` is deliberate at the approval layer; transport must still revalidate and pin the destination IP at connection time.
- The general tool registry, strict per-tool schemas, process/container isolation, egress firewall, and kill-on-cancel remain incomplete.
- Approval action payload size is capped at 64 KiB; unusual non-JSON parameter types are not accepted.

### Exact next requirements

1. `ART-AUTH-001` — immutable policy-bound execution gateway and action-time policy validation.
2. `ART-AUTH-003` — fixed-schema tool registry and argument validation.
3. Complete `ART-AUTH-002` — require approval consumption in the actual dispatch path.
4. `ART-AUTH-002g` / `ART-AUTH-005` — authenticated operator identity and role-based control API.
5. `ART-ISOLATION-001/002` — isolated worker execution and network egress enforcement.

Do not mark parent `ART-AUTH-002` VERIFIED until execution integration and authenticated operator control are implemented and tested.


## Batch 2.2.4 — closed-world tool argument registry

**Date:** 2026-10-24  
**Requirements addressed:** `ART-AUTH-003a` through `ART-AUTH-003d`; partial progress on `ART-AUTH-003`.

### Files created or modified

- `appsec_agent/tool_registry.py` — closed-world tool allowlist and strict argument validation.
- `appsec_agent/approval.py` — registry validation enforced on both approval request and consumption.
- `tests/test_approval.py` — unknown tool, extra parameter, unsafe HTTP method, boolean-as-integer and boundary regression cases.
- `docs/implementation/requirements-register.md`, `docs/implementation/capability-parity-matrix.md`, `README.md`, `CHANGELOG.md`, `appsec_agent/__init__.py` — requirements, limitations and version updates.

### Implemented behavior

- Only explicitly registered tool names are accepted; this batch registers `http_request` only.
- The schema requires `method`, permits only GET/HEAD/OPTIONS, and rejects arbitrary headers/body/shell fields.
- Optional `auth_profile` must be an identifier reference, not a raw header value.
- Optional `max_response_bytes` must be an integer (not a boolean) between 1 and 250000.
- Unknown fields, missing fields, invalid types and unsupported tool names fail closed before an approval can be requested or consumed.

### Validation

- Focused approval/runtime tests: `python -m pytest -q tests/test_approval.py tests/test_runtime_store.py` — **32 passed**.
- `python -m pytest -q` — **68 passed, 7 subtests passed** after both approval and registry changes. `python -m compileall -q .` passed; version and catalog checks are included in the clean release validation.

### Limitations and next requirements

- The registry is enforced in approval request/consumption but no worker/scanner executor exists to enforce it immediately before dispatch. Parent `ART-AUTH-003` therefore remains `IN_PROGRESS`.
- Only `http_request` is registered; adding tools requires a reviewed fixed schema and tests, not arbitrary command passthrough.
- Next: `ART-AUTH-001` action-time policy gateway, wire approval consumption into dispatch, authenticated operator API (`ART-AUTH-002g` / `ART-AUTH-005`), and isolated execution (`ART-ISOLATION-001/002`).


## Batch 2.2.5 — policy-bound authorization gateway and execution ledger

**Date:** 2026-10-24  
**Requirements addressed:** `ART-AUTH-001b` through `ART-AUTH-001e`, `ART-AUTH-002h`, `ART-AUTH-003e`, `ART-RUNTIME-015`; parent `ART-AUTH-001/002/003` remain `IN_PROGRESS`.

### Files created or modified

- `appsec_agent/authorization.py` — central authorization gateway for claimed `tool_action` queue tasks; policy/scope and registry revalidation; exact approval checks; atomic one-time consumption and execution authorization record; a second authorization check at the execution gate; fail-closed block before `running` until an isolated backend exists; evidence-backed atomic completion contract.
- `appsec_agent/runtime_store.py` — schema v3 `execution_attempts`, approval revocation columns, chained runtime-event hashes and stored audit head, verification API, cancellation propagation and recovery-required handling after lease loss following approval consumption.
- `appsec_agent/approval.py` — revocation API and schema validation at consumption; removed redundant duplicate schema-validation passes.
- `appsec_agent/tool_registry.py` — fixed tool version/risk/approval/timeout/response-cap metadata for the sole registered `http_request` tool.
- `agent.py` — `approval-revoke` and `audit-verify` runtime actions.
- `tests/test_authorization.py`, `tests/test_approval.py` — exact-action gateway, policy/parameter/target substitution, expiry, revocation, replay, lease/cancellation, crash recovery, evidence commit, audit tampering/redaction and schema migration cases.
- `README.md`, `CHANGELOG.md`, requirements register, capability parity matrix, progress journal, package version — updated for v2.2.5 and documented limitations.

### Implemented behavior

- The gateway only accepts `tool_action` tasks with an exact fixed set of fields and validates registered tool arguments again at authorization time.
- It recomputes the policy digest from the loaded policy and binds an authorization digest to assessment/job/task, current scope version, target/operation, canonical arguments, tool version, unique action ID, approval identity and expiry.
- Lease validation, job-state validation, approval checks, approval consumption and execution authorization persistence occur in one SQLite transaction. Replayed action IDs and parameter substitution fail closed.
- Before entering `running`, the gateway rechecks the lease, current policy, cancellation, approval expiry/revocation and recomputes the complete action digest from persisted state. It then deliberately blocks because no isolated execution backend exists. The completion contract commits the task and execution record atomically only when the result points to a persisted evidence record matching the exact action ID, target and operation; unit tests seed the trusted-running state to test this commit contract, not to claim a real worker ran.
- Runtime events are redacted and hash-chained with a stored head. Tests detect event modification and tail deletion. This is tamper-evident against partial edits, not against a privileged attacker rewriting the database and head together.
- Cancellation marks active execution attempts cancelled. A lease expiry after approval consumption becomes failed/recovery-required rather than automatically replaying the same action.

### Validation

- Baseline before edits: `python -m pytest -q` — **68 passed, 7 subtests passed**.
- Focused gateway/approval/runtime tests: `python -m pytest -q tests/test_authorization.py tests/test_approval.py tests/test_runtime_store.py` — **55 passed**.
- Full suite: `python -m pytest -q` — **91 passed, 7 subtests passed**.
- `python -m compileall -q .` — passed; `python artemis.py --version` — `ARTEMIS 2.2.5`; `python artemis.py --validate-catalog` — valid, 12 runnable tests, 4 framework maps.
- `python artemis.py --policy policy.example.json --dry-run --provider offline` — passed with `network_requests: 0`.
- CLI smoke test: create job, request approval, revoke approval and verify audit chain — all exit status 0.
- Clean release ZIP: archive integrity check passed; clean extraction reran `python -m pytest -q` (**91 passed, 7 subtests passed**), compilation, version, catalog validation and offline dry-run successfully.
- `python -m ruff check appsec_agent agent.py tests` could not run because Ruff is not installed (`No module named ruff`); no network install attempted.
- **Register recount:** including lowercase granular IDs (`ART-AUTH-001a`, etc.), the actual Markdown table contains 85 unique requirement rows. The register snapshot reflects 56 VERIFIED, 3 IMPLEMENTED, 8 IN_PROGRESS, 18 NOT_STARTED and 0 BLOCKED. This is the prior 78-row baseline plus seven new granular requirements; no requirement IDs were dropped.

### Defects, limits and security notes

- **No isolated worker executor exists.** The gateway records authorization but deliberately blocks before entering `running` and never invokes a tool handler. Completion/failure lifecycle methods are persistence contracts for a future trusted supervisor; unit tests simulate the supervisor-created running state. Tool timeout metadata is declarative until a worker supervisor enforces it.
- The legacy `engine.run` path is not wired to queued `tool_action` dispatch; its deterministic built-in checks still use the existing in-process HTTP client and policy gate. Therefore this batch is not a universal execution boundary and does not claim that all tool calls require approval.
- No authenticated multi-user operator API/role enforcement exists; CLI identity remains tied to the current OS account.
- The event hash chain is local integrity evidence, not a cryptographic anchor external to the database. Protecting against a privileged database rewrite requires an external append-only log or separately protected signing key.
- Actual process termination, container isolation, egress firewall enforcement and worker crash/cancel integration remain open (`ART-ISOLATION-001/002`, `ART-RUNTIME-013/014`).

### Next dependency-ready batch

Implement a trusted isolated worker supervisor first: pinned runtime image, non-root execution, CPU/memory/process limits, wall-clock timeout and kill-on-cancel, filesystem restrictions, and default-deny egress. Then bind the registered `http_request` handler to that supervisor and wire `engine.run`/queue task dispatch through `AuthorizationGateway`; only then can end-to-end execution authorization and cancellation be verified.


## Batch 2.2.6 — verify existing claims and close feasible implementation gaps

**Date:** 2026-10-24  
**Version:** 2.2.6  
**Requirements verified/advanced:** `ART-ASSET-002`, `ART-TRACE-002`, `ART-POLICY-004`, `ART-EVIDENCE-004/005`, `ART-PLAN-005`, `ART-VERIFY-002`, `ART-AUTH-002g`, `ART-AUTH-005`, `ART-BENCH-001`, `ART-OPS-001/002`; progress on `ART-PLAN-002`, `ART-VERIFY-001`, `ART-BENCH-002`.

### Implemented

- Asset deduplication now records repeated sightings, preserves first-seen values, and records attribute and scope conflicts. Tests verify conflict semantics.
- Trace search is verified for filters, current-intent exclusion and hard result caps. Proxy routing is explicitly tested to fail before DNS resolution.
- EvidenceStore creates a chained JSONL manifest. Verification checks sequence, previous hashes, record hashes, row counts and missing/unmanifested rows. Export requires a valid chain and includes per-file hashes and redaction status.
- Evidence retention is explicit and dry-run by default. Apply mode validates the manifest, archives the run and only then deletes the source directory.
- Added evidence-bound verification decisions with a fixed deterministic checker set for security headers, cache policy, content type, disclosure headers, CORS and server-error status. Decisions require original and retest evidence, exact target match and a distinct verifier ID; caller-supplied outcomes cannot override checker output. Full finding-class coverage and automatic blackboard claim promotion remain open, so `ART-VERIFY-001` remains `IN_PROGRESS`.
- Added deterministic explainable candidate ranking and exposed scores to the model planner. Benchmark-driven improvement has not been demonstrated, so `ART-PLAN-002` remains `IN_PROGRESS`.
- Engine startup now reconciles previously executed test statuses against durable facts/evidence and marks unsupported outcomes `stale` for review.
- Added loopback-only bearer-token operator API with server-side role mapping and tests for authentication, spoofing, role separation, bounded body size, job cancellation, approval decision and revocation. API has no TLS or external identity provider and rejects non-loopback binds.
- Added local runtime health reporting, SQLite online backup/restore helpers, schema/integrity checks and tests.
- Added a versioned sanitized positive/negative benchmark corpus and evaluator for precision/recall/F1, runtime, request count and model cost. `ART-BENCH-002` remains `IN_PROGRESS` because no real scanner baseline or thresholds have been measured.

### Verification

- Pre-batch baseline: `python -m pytest -q` — **91 passed, 7 subtests passed**.
- Focused tests: evidence lifecycle, planner reconciliation, operations, local HTTP/proxy and operator API — passed.
- Full suite after implementation: `python -m pytest -q` — **118 passed, 7 subtests passed**.
- `python -m compileall -q .` — exit 0; `python artemis.py --version` — `ARTEMIS 2.2.6`; `python artemis.py --validate-catalog` — valid, 12 runnable tests, 4 framework maps.
- `python artemis.py --policy policy.example.json --dry-run --provider offline` — exit 0, `network_requests: 0`.
- CLI `serve-api` smoke test: loopback bind, bearer-token-authenticated `/health`, SQLite integrity `ok`; no target traffic.
- `python -m ruff check appsec_agent agent.py tests` — unavailable because Ruff is not installed (`No module named ruff`); no package installation or network request attempted.
- Release ZIP integrity passed; clean extraction reran compile, version, catalog validation, the full suite (**118 passed, 7 subtests passed**) and offline dry run (`network_requests: 0`). SHA-256: `c52e43d2d32094173b26dda9fd6f1ae1edbe0ec185cdf7c60feea16abe8f8ed5`.

### Requirement register recount

- Total: **85 unique requirements**.
- `VERIFIED`: **68**; `IN_PROGRESS`: **9**; `NOT_STARTED`: **8**; `IMPLEMENTED`: **0**; `BLOCKED`: **0**.
- The three previous `IMPLEMENTED` items were only promoted after targeted regression tests passed.

### Still open — do not claim complete

- `ART-AUTH-001/002/003/004`: real handler dispatch, engine integration and end-to-end authorization/prompt-injection fixtures.
- `ART-VERIFY-001`: execute a trusted independent deterministic verifier; current module records evidence-bound decisions but does not run the verifier.
- `ART-RUNTIME-013/014`, `ART-ISOLATION-001/002`: process resource ceilings, actual process/container cancellation and cleanup, least privilege, filesystem isolation and external egress enforcement. No Docker, Podman, bubblewrap or Firejail runtime was found in the current environment, so the worker isolation requirements cannot be honestly marked verified here.
- `ART-BUDGET-001`: model token/cost ledger and hard cost preflight enforcement.
- `ART-INT-002/003`: fixed-schema scanner and MCP/skill adapters; there is no isolated executor to host them.
- `ART-TRAFFIC-001`: full traffic sequence capture/proxy integration beyond direct request evidence.
- `ART-UI-001`: persisted backend-backed dashboard.
- `ART-LICENSE-001`: legal compatibility review is an external human/legal decision.

### Next dependency-ready batch

Implement a real, pinned isolated worker supervisor and default-deny egress boundary; then route registered tool execution and the legacy engine through `AuthorizationGateway`. Do not add live scanner adapters before the supervisor is available and tested.

## Batch 2.2.7 — pinned-container worker supervisor (fail-closed)

**Date:** 2026-10-24  
**Requirements addressed:** partial `ART-RUNTIME-013`, `ART-RUNTIME-014`, `ART-ISOLATION-001`; `ART-ISOLATION-002` remains `NOT_STARTED` because scoped egress is not implemented.  
**Dependencies inspected:** `AuthorizationGateway`, fixed-schema `http_request` registry, persistent queue lease/cancel APIs and the existing completion/evidence contract.

### Implementation

- Added `appsec_agent/worker_supervisor.py` with `ContainerWorkerSupervisor` and bounded `WorkerLimits`.
- Requires a SHA-256-pinned container image, trusted fixed entrypoint, absolute configured runtime executable, and `--pull=never`; tasks can supply only a bounded JSON payload, not a command or executable.
- Container arguments request no network, read-only root filesystem, non-root UID/GID 65532, no capabilities, no-new-privileges, bounded CPU/memory/swap/PIDs/tmpfs and no host mounts. The image's default seccomp profile is not replaced.
- Added wall-clock timeout, bounded stdin/stdout/stderr, strict JSON completion contract with non-empty evidence references, explicit cancellation, container stop, and runtime process-group termination.
- Network-required execution fails closed. `http_request` is therefore still not executable through this supervisor until an externally enforced scoped egress proxy exists.

### Validation and environment limitations

- `python -m pytest -q tests/test_worker_supervisor.py` — **10 passed**. A fake runtime verifies flags, input/command separation, output cap, timeout, cancellation and result validation; this is not proof of OS/container isolation.
- Environment check: Docker, Podman, bubblewrap and Firejail are unavailable. `unshare --net -- true` failed with `Operation not permitted`. A real container integration test cannot be run here.
- Queue cancellation is not yet connected to `ContainerWorkerSupervisor.cancel`, and the supervisor is not yet called by `AuthorizationGateway` or the legacy engine. Therefore `ART-RUNTIME-013`, `ART-RUNTIME-014`, and `ART-ISOLATION-001` remain `IN_PROGRESS`; no execution claims are marked verified.
- No live/public/production traffic was sent.

### Next integration blocker

Implement a supervisor registry keyed by durable execution ID and wire runtime job cancellation to it, then route authorized tool dispatch through this registry. Before enabling HTTP actions, implement and test a policy-aware egress proxy outside the worker process that checks each destination and pins/revalidates the address; do not switch the container to host networking or unrestricted bridge networking.


## Batch 2.2.8 — legacy request authorization, scoped egress components and supervisor hardening

**Date:** 2026-10-24  
**Requirements:** verified subrequirements `ART-AUTH-001f`, `ART-RUNTIME-013a`, `ART-ISOLATION-002a/b`; parent `ART-AUTH-001/002/003`, `ART-RUNTIME-013/014`, `ART-ISOLATION-001/002` remain incomplete where execution integration or real enforcement is required.

### Verified starting state

- Source was inspected from the v2.2.7 clean extraction; no `.git` metadata is present, so branch/working-tree state cannot be established.
- Baseline before edits: `python -m pytest -q` — **128 passed, 7 subtests passed**.
- Actual package version before edits: `ARTEMIS 2.2.7`.

### Implemented

- `InlineRequestAuthorizationGateway` is now mandatory in `LabHTTPClient.request`. It checks the current policy digest, validates URL scope and allows only GET/HEAD/OPTIONS in the legacy in-process engine. Policy validation now also enforces an explicit `allowed_ports` list, defaulting to the base URL port/scheme port and denying alternate ports unless configured. It logs authorization outcomes without logging query strings and is followed by independent transport URL validation, DNS/IP checks, pinned socket connection, TLS verification and `allow_redirects=False`. State-changing operations must use the exact-action queue path and are not allowed in legacy mode.
- `AuthorizationGateway` now rechecks that approval status remains `consumed`, unrevoked and unexpired before starting and before committing an evidence-backed result. Added expiry-race tests.
- Added `ScopedEgressPolicy` and `ScopedConnectProxy`: exact host/port allowlist; live assessment/policy context callback on each CONNECT; all DNS answers checked; explicit CIDR exceptions for isolated lab destinations only; signed in-process decision objects; pinned socket connect; redacted allow/deny audit events; plaintext proxy requests rejected. Tests include an actual loopback tunnel to a local echo fixture.
- Added `scripts/worker-egress-firewall.py`, which prints rules by default and only applies after `--apply`, root/runtime checks, refusal to overwrite an existing table, and post-apply verification. Rules permit a dedicated worker subnet to reach only the configured broker endpoint and drop other worker-subnet input/forward traffic.
- `ContainerWorkerSupervisor` now inspects the local image and verifies its exact SHA-256 repository digest before launch, and forced-removes containers during timeout/cancel cleanup. Tests verify digest mismatch blocks launch and cleanup commands are issued. Added opt-in `tests/integration/test_container_runtime.py` for real Docker/Podman controls.

### Validation

- Baseline: `python -m pytest -q` — **128 passed, 7 subtests passed**.
- Focused authorization, egress, firewall, supervisor and legacy HTTP tests: `python -m pytest -q tests/test_authorization.py tests/test_worker_supervisor.py tests/test_scoped_egress.py tests/test_egress_firewall.py tests/test_local_http.py` — **54 passed** (exit 0).
- Final full suite: `python -m pytest -q` — **146 passed, 1 skipped, 11 subtests passed** (exit 0). The one skip is the opt-in real Docker/Podman integration test because no runtime/image is configured.
- Firewall rule-generator dry run exited 0 and printed the dedicated `inet artemis_worker_egress` table; no firewall changes were made.
- Environment probe: no Docker, Podman or nft executable found. `unshare --net -- true` exited 1 with `Operation not permitted`. Real container and host network enforcement could not be tested here.

### Explicit limitations

- The CONNECT broker and firewall generator are not attached to the worker network; the supervisor continues to use `--network=none`, and network-required actions still fail closed. An application proxy alone is not claimed as a network boundary.
- The legacy engine is now behind a mandatory scope gate for read-only requests, but it is not yet routed through the persistent exact-action approval ledger.
- Queue cancellation is not wired to the supervisor active-execution registry; no handler dispatch path is enabled.
- HTTPS CONNECT cannot inspect encrypted URL paths; the HTTP client must continue to enforce path/method scope and disable redirects. A real Linux deployment must separately verify the worker firewall, broker topology and redirect behavior before enabling network access.
- No public or production targets were contacted, and no firewall rules were applied.

### Next dependency-ready batch

Wire the durable execution registry to `ContainerWorkerSupervisor` and make cancellation terminate the exact container before acknowledging termination. Then integrate the broker with a dedicated worker network and validate it with the opt-in real-runtime test plus a Linux nftables integration fixture. Only after that should the queue gateway dispatch the registered `http_request` handler.


## Batch 2.2.9 — durable cancellation-to-supervisor contract

**Date:** 2026-10-24  
**Requirements:** verified subrequirement `ART-RUNTIME-014a`; parent `ART-RUNTIME-014`, `ART-AUTH-001/002/003`, and `ART-ISOLATION-001/002` remain incomplete.

### Verified starting state

- Source package version: `2.2.8`.
- `git status --short --branch` — unavailable because this source tree has no `.git` metadata.
- Baseline `python -m pytest -q` — **146 passed, 1 skipped, 11 subtests passed**.
- Reviewed the requirements register, capability parity matrix, progress journal, changelog, `worker_supervisor.py`, `runtime_store.py`, `authorization.py`, `scoped_egress.py`, `engine.py`, `http_client.py` and relevant tests.

### Implementation

- Added `RuntimeStore.register_execution_canceller(callback)`. For every durable `execution_attempts.state='running'` row, `cancel_job()` invokes a registered callback and requires a positive termination confirmation before committing job/task/execution cancellation. Missing, false or throwing callbacks prevent cancellation from being acknowledged. The transaction rolls back state changes, and an unconfirmed-cancellation event is attempted in a separate transaction.
- `ContainerWorkerSupervisor` now derives stable container names from the validated execution ID. If its in-memory process handle is missing after controller restart, `cancel()` inspects that stable name, stops/removes the container and verifies that it is absent. A missing container returns false rather than being treated as proof of completion.
- Added tests for callback absence, unconfirmed termination rollback, confirmed cancellation, stable container naming and cleanup of a persisted container after controller restart.

### Validation

- Baseline `python -m pytest -q` — **146 passed, 1 skipped, 11 subtests passed**.
- Focused `python -m pytest -q tests/test_runtime_store.py tests/test_worker_supervisor.py` — **33 passed**.
- Final full-suite, compile, catalog, offline dry-run and clean-extraction results are recorded in the release summary.

### Remaining limitations

- There is still no production queue dispatcher that calls `AuthorizationGateway`, starts a supervisor for a durable execution ID, validates durable evidence and commits the result. `AuthorizationGateway.begin_execution()` intentionally blocks because this environment cannot attest to an enforced worker/egress boundary.
- The store's supervisor callback must be explicitly registered by a trusted runtime bootstrap. There is no active network-capable worker path today.
- Docker/Podman and nftables are unavailable; network namespace creation is not permitted. No actual container/network isolation or firewall integration test can run here. `ART-ISOLATION-002` remains incomplete and the worker remains `--network=none`.
- No public or production targets were contacted and no host firewall rules were applied.


## Batch 2.2.10 — durable queue dispatch integration seam

**Date:** 2026-10-24  
**Version:** 2.2.10  
**Requirement verified:** `ART-RUNTIME-016`.

### Implemented

- Added `appsec_agent/dispatcher.py` with `QueueDispatcher`: claims only `tool_action` tasks, invokes `AuthorizationGateway.authorize_task`, and immediately calls `begin_execution` for policy/lease/approval/action revalidation. Authorization failures are terminally failed without automatic retry; audit denial remains in the runtime event chain.
- Added optional task-type filtering to `RuntimeStore.claim_next` while preserving existing callers and default selection semantics.
- Dispatcher registers `ContainerWorkerSupervisor.cancel` as the durable cancellation callback when a supervisor is configured.
- Added `--runtime-action dispatch-once`; trusted image/entrypoint configuration comes from `ARTEMIS_WORKER_IMAGE` and `ARTEMIS_WORKER_ENTRYPOINT_JSON`, never task input.
- The dispatcher intentionally does not run a handler: the current gateway returns `blocked/isolated_backend_unavailable` until independently enforced egress and real container isolation are verified. No network requests are made.

### Verification

- Baseline before changes: `python -m pytest -q` — **150 passed, 1 skipped, 11 subtests passed**.
- Focused tests: `python -m pytest -q tests/test_dispatcher.py tests/test_runtime_store.py tests/test_authorization.py` — **52 passed**.
- Full suite: `python -m pytest -q` — **155 passed, 1 skipped, 11 subtests passed** (exit 0).
- `python -m compileall -q .` — exit 0.
- `python artemis.py --version` — `ARTEMIS 2.2.10` (exit 0).
- `python artemis.py --validate-catalog` — valid, 12 runnable tests, 4 framework maps (exit 0).
- `python artemis.py --policy policy.example.json --dry-run --provider offline` — exit 0, `network_requests: 0`.
- `python -m ruff check appsec_agent agent.py tests` — unavailable, `No module named ruff` (exit 1); no dependency installation attempted.
- Requirements recount at v2.2.10: 92 unique IDs: 75 VERIFIED, 13 IN_PROGRESS, 4 NOT_STARTED, 0 IMPLEMENTED, 0 BLOCKED.
- CLI smoke: `python artemis.py --runtime-action dispatch-once --policy policy.example.json --runtime-db <temporary-db> --worker-id cli-smoke` — exit 0, explicit idle result, no target traffic.
- Clean-extraction ZIP validation: archive integrity passed; `python -m pytest -q` — **155 passed, 1 skipped, 11 subtests passed**; compilation, version, catalog and offline dry-run checks passed.

### Limits

- `ART-RUNTIME-016` verifies the durable queue-to-gateway fail-closed integration, not successful tool execution.
- `ART-AUTH-001/002/003`, `ART-ISOLATION-001/002`, `ART-RUNTIME-013/014` remain in progress. No container runtime or host firewall enforcement was available; no network-capable action was executed.

## Batch 2.2.11 — hosted model budget enforcement

**Date:** 2026-10-24
**Requirement:** `ART-BUDGET-001` promoted to `VERIFIED` after implementation and boundary tests.

### Implementation

- Added `appsec_agent/budget.py` with a persisted per-assessment ledger for request count, input/output/total token counts and configured USD cost.
- Hosted model calls require an explicit `llm_budget` policy containing the exact provider/model, request and token ceilings, cost ceiling, and operator-maintained input/output price rates. The provider/model must match the effective environment configuration.
- Engine initializes and validates the ledger before making target requests. The provider call has a configured output-token cap; the ledger reserves worst-case input/output/cost before the call and settles with provider-reported usage where available.
- Input admission uses UTF-8 byte length as a conservative token bound. Provider usage overruns or exceeding the configured cap persist an exhausted state and block subsequent model calls. Missing usage keeps the conservative reservation charged. Budget exhaustion stops planner selection; it does not silently invoke another hosted call.
- Added `docs/operations/model-budget.md` with setup guidance and explicit limitations. Updated the README, changelog and capability matrix.

### Tests and validation

- `python -m pytest -q tests/test_budget.py tests/test_planner_reconciliation.py tests/test_runtime_store.py` — **32 passed** before the two final planner integration tests were added.
- `python -m pytest -q tests/test_budget.py` — **9 passed**.
- Full suite: `python -m pytest -q` — **164 passed, 1 skipped, 11 subtests passed** (exit 0).
- `python -m compileall -q .` — exit 0.
- `python artemis.py --version` — `ARTEMIS 2.2.11` (exit 0).
- `python artemis.py --validate-catalog` — valid, 12 runnable tests, 4 framework maps (exit 0).
- `python artemis.py --policy policy.example.json --dry-run --provider offline` — exit 0, `network_requests: 0`.
- Requirements recount: 92 unique IDs: 76 VERIFIED, 12 IN_PROGRESS, 4 NOT_STARTED, 0 IMPLEMENTED, 0 BLOCKED.

### Limits

- This is a local single-process assessment ledger, not distributed accounting across concurrent hosts.
- USD protection depends on the operator setting accurate prices for the exact provider/model; this is not a provider billing guarantee.
- Real container isolation, worker-connected scoped egress, successful queue handler execution, full scanner/MCP adapters, traffic recording, dashboard, broader verification coverage and legal review remain incomplete.

## Batch 2.2.12 — traffic correlation and local operations dashboard

**Date:** 2026-10-24
**Requirements:** partial progress on `ART-TRAFFIC-001` and `ART-UI-001`; both remain `IN_PROGRESS` because their full acceptance criteria exceed the current implementation.

### Implementation

- `EvidenceStore.capture()` now assigns unique traffic IDs, persists redacted exchange metadata and body hashes in `traffic.jsonl`, and retains the full redacted evidence record with its traffic ID. The evidence sequence resumes from existing evidence IDs on restart to avoid ordinary single-writer collisions.
- Transport failures now receive unique evidence and traffic IDs rather than the constant `ev-transport` placeholder.
- Findings inherit traffic IDs only from evidence IDs that resolve to persisted traffic records. Caller-supplied traffic IDs are rejected unless they already exist.
- `EvidenceStore.verify_traffic()` verifies unique IDs, evidence resolution, response hash consistency, finding references and the chained evidence manifest. Added `--verify-traffic RUN_DIR`; exports now include `traffic.jsonl`.
- Added a same-origin dashboard served at `/` by the loopback operator API. It reads persisted health/jobs/tasks and supports authorized job cancellation. Job/task responses now omit raw task inputs/results; server role checks remain authoritative.
- Added `RuntimeStore.list_jobs()` and API integration tests for dashboard delivery, auth-protected data, sensitive field omission and role-based cancellation.

### Validation

- `python -m pytest -q tests/test_evidence_lifecycle.py tests/test_local_http.py` — **15 passed** after traffic journal additions.
- `python -m pytest -q tests/test_operator_api.py` — **7 passed**.
- Full suite: `python -m pytest -q` — **170 passed, 1 skipped, 11 subtests passed** (exit 0).
- Requirements register recount: 92 IDs; 76 VERIFIED, 14 IN_PROGRESS, 2 NOT_STARTED.

### Limits

- Traffic capture is client-level and redacted; no transparent proxy, raw/binary capture, or coverage of requests made outside `LabHTTPClient`.
- The dashboard currently covers health, jobs, task state and cancellation only. Findings/assets/logs/approval views and remote TLS/identity-provider integration remain absent.

## Batch 2.2.13 — persisted assessment dashboard

**Date:** 2026-10-24
**Requirement:** `ART-UI-001` promoted to `VERIFIED` for the documented loopback-only scope.

### Implementation

- Added `RuntimeStore.list_approvals()` and extended the operator API with persisted `/assessments`, `/assessments/<id>` and `/approvals` views.
- Assessment detail includes sanitized summary, test statuses, findings, assets, claims, event logs and traffic journal records. File access is bounded, rejects symlinked assessment directories/files and checks resolved paths against the configured run root.
- Added recursive redaction for secret-like fields and URL query parameters. Job/task API responses omit raw input and result fields.
- Expanded the same-origin dashboard with assessment and approval views plus approval decision/rejection/revocation controls. Mutating operations still use server-side roles; the browser does not choose its own role. No third-party scripts are loaded.
- Added integration tests for assessment data loading, secret redaction, dashboard security headers and control wiring. Existing tests cover role enforcement for cancellation and approval actions.

### Validation

- `python -m pytest -q tests/test_operator_api.py` — **8 passed** before final UI assertion additions.
- Full suite: `python -m pytest -q` — **171 passed, 1 skipped, 11 subtests passed** (exit 0).
- `ART-UI-001` acceptance is limited to a local loopback dashboard; remote TLS/identity provider and multi-host access are not claimed.

## Batch 2.2.14 — expanded deterministic verification and benchmark thresholds

**Date:** 2026-10-24
**Requirements:** `ART-PLAN-002` verified by a synthetic coverage benchmark; additional progress on `ART-VERIFY-001` and `ART-BENCH-002`, which remain `IN_PROGRESS` due broader finding-class coverage and missing real scanner baseline/CI wiring.

### Implementation

- Added fixed verifiers for cookie flags, advertised risky HTTP methods and anonymous authentication boundaries.
- Evidence capture now stores only boolean Secure/HttpOnly/SameSite metadata for Set-Cookie headers so cookie verification does not require retaining cookie values.
- Persisted verification decisions now reconcile into claims by exact `finding_id` provenance. A corroborated decision can mark a claim verified only when original and retest evidence both resolve; not-reproduced/inconclusive decisions map to `inconclusive` rather than falsely marking a finding disproved.
- Restart reconciliation replays the latest durable verification decision to recover from a crash between verification-history append and blackboard update.
- Added `compare_to_baseline()` for explicit named baselines and thresholds across precision/recall/F1 regressions and runtime/request/model-cost increases. No synthetic baseline is presented as a real scanner baseline.
- Added a three-case synthetic planner coverage benchmark showing category-coverage ranking selects previously unobserved categories over higher-priority repeated categories; the scoring rationale remains explicit.

### Tests

- `python -m pytest -q tests/test_evidence_lifecycle.py tests/test_planner_reconciliation.py` — **21 passed** before final benchmark and verifier cases were combined.
- `python -m pytest -q tests/test_benchmark.py tests/test_evidence_lifecycle.py` — **22 passed** before the final reconciliation additions.
- Full suite: `python -m pytest -q` — **178 passed, 1 skipped, 11 subtests passed** before the final planner benchmark was added; rerun is required for final package validation.

### Limits

- Scenario, workflow-invariant and SARIF-derived finding classes still lack complete independent verifier coverage.
- A real scanner-generated benchmark baseline and CI regression gate remain unavailable; only the comparison mechanism is implemented and tested.

## Batch 2.2.15 — CI-friendly benchmark regression CLI

**Date:** 2026-10-24
**Requirement:** further progress on `ART-BENCH-002`; remains `IN_PROGRESS` because no provenance-backed real scanner baseline or CI workflow is available.

- Added `--benchmark-compare FILE`, which validates a bounded regular JSON input, runs the strict baseline/threshold comparison, emits machine-readable JSON and exits 2 on regression or invalid input.
- Added subprocess tests for passing and failing comparisons and documented a CI integration format. Example values are explicitly illustrative, not a measured baseline.
- `python -m pytest -q tests/test_benchmark.py` — **7 passed**.
- Full suite after the final 2.2.15 changes: `python -m pytest -q` — **179 passed, 1 skipped, 11 subtests passed** (exit 0).
- `python -m compileall -q .` — exit 0.
- `python artemis.py --version` — `ARTEMIS 2.2.15` (exit 0).
- `python artemis.py --validate-catalog` — valid, 12 runnable tests, 4 framework maps (exit 0).
- Offline dry run — exit 0, `network_requests: 0`.
- Clean-extraction regression suite — **179 passed, 1 skipped, 11 subtests passed**; compilation, version, catalog and dry-run checks passed.
- Register recount: 92 IDs: 78 VERIFIED, 12 IN_PROGRESS, 2 NOT_STARTED, 0 IMPLEMENTED-but-unverified, 0 BLOCKED.


## Batch 2.2.16 — legacy request override hardening

**Date:** 2026-10-24  
**Requirement:** progress on `ART-AUTH-004`; remains `IN_PROGRESS`.

### Implementation

- Extended `InlineRequestAuthorizationGateway` to validate request overrides in addition to URL, method and policy digest. Read-only GET/HEAD/OPTIONS requests reject request bodies, malformed or oversized header maps, CRLF/NUL injection, and headers that can override routing, authentication, proxy behavior, transport framing, forwarding or HTTP method semantics.
- `LabHTTPClient` now passes headers/body presence to the authorization gateway and validates the auth-profile selector before opening a session. Rejections happen before request-budget consumption or network transport.
- Added adversarial tests for `Host`, `Authorization`, `Transfer-Encoding`, method-override headers, CRLF injection, read-only request bodies and malformed auth selectors. Audit records retain reason codes and do not include the supplied header values.

### Validation

- `python -m pytest -q tests/test_authorization.py tests/test_local_http.py` — **32 passed**.
- Full suite: `python -m pytest -q` — **180 passed, 1 skipped, 11 subtests passed** (exit 0).
- `python -m compileall -q .` — exit 0.
- `python artemis.py --version` — `ARTEMIS 2.2.16` (exit 0).
- `python artemis.py --validate-catalog` — valid, 12 runnable tests, 4 framework maps (exit 0).
- Offline dry run — exit 0, `network_requests: 0`.
- Requirements register recount: 92 unique IDs; 78 VERIFIED, 12 IN_PROGRESS, 2 NOT_STARTED.
- Clean extraction of `ARTEMIS-appsec-2.2.16.zip`: `python -m pytest -q` — **180 passed, 1 skipped, 11 subtests passed**; compile, version, catalog and offline dry-run checks also passed. Archive `ZipFile.testzip()` returned no corrupt member.

### Limits

- This is defense-in-depth for the legacy HTTP request path, not a substitute for queue-bound exact-action authorization or isolated execution. `ART-AUTH-004` remains `IN_PROGRESS`; target-content prompt-injection end-to-end fixtures remain outstanding.


## Batch 2.2.17 — defensive SARIF ingestion

**Date:** 2026-10-24  
**Requirement:** hardened `ART-INT-001` importer; status remains `VERIFIED` for import-only scope.

### Implementation

- SARIF import accepts documented 2.0.0/2.1.0 versions, rejects symlink/non-regular/oversized inputs, reads at most 10 MiB even if a file changes after metadata inspection, and bounds runs, rules, results, titles, URIs and tags.
- Invalid roots, versions and malformed records are safely skipped with index-only reason-code audit events; raw scanner text is not copied into warning events. Unsupported severity labels normalize to `warning`. Duplicate findings are not counted as newly imported.
- Added `tests/test_sarif.py` for valid data, severity mapping, malformed inputs, limits, symlinks, redacted audit events and deduplication.

### Validation

- Focused SARIF/core tests: **39 passed, 11 subtests passed** before the final duplicate-import case.
- Full suite: `python -m pytest -q` — **186 passed, 1 skipped, 11 subtests passed** (exit 0).
- `python -m compileall -q .` — exit 0.
- `python artemis.py --version` — `ARTEMIS 2.2.17` (exit 0).
- `python artemis.py --validate-catalog` — valid, 12 runnable tests, 4 framework maps (exit 0).
- Offline dry run — exit 0, `network_requests: 0`.
- Requirements register recount: 92 unique IDs; 78 VERIFIED, 12 IN_PROGRESS, 2 NOT_STARTED. Clean extraction of `ARTEMIS-appsec-2.2.17.zip`: **186 passed, 1 skipped, 11 subtests passed**; compile, version, catalog and offline dry-run checks passed. `ZipFile.testzip()` reported no corrupt member.

### Limits

- SARIF is still an import-only integration. `ART-INT-002` scanner execution adapters and `ART-INT-003` MCP/skill adapters remain `NOT_STARTED`; no scanner is invoked by this importer.


## Batch 2.2.18 — fixed integration contracts and provenance release gate

**Date:** 2026-10-24  
**Version:** 2.2.18  
**Requirements advanced:** `ART-INT-002`, `ART-INT-003`; `ART-LICENSE-001` provenance documentation added but remains open.

### Implemented

- Added a closed-world scanner adapter registry for Nuclei, ZAP Baseline and Trivy Config. Inputs are target URLs and bounded timeout/output limits; no user-provided executable, shell fragment, arbitrary argv, or fake trusted image digest is accepted. The registry creates a hashed JSON payload and explicitly reports execution disabled until a pinned scanner image and verified isolated worker are configured.
- Added an MCP/skill capability registry with explicit permissions, required object fields, `additionalProperties=false`, supported primitive field types, string bounds/enums, input/output byte caps and elapsed-time metadata. Unregistered capabilities and ungranted permissions fail closed. Production use remains gated on a trusted transport that enforces hard cancellation inside the verified worker; this module is not connected to a live MCP server.
- Added 11 tests for scanner target/schema/resource validation and MCP permission/schema/output enforcement.
- Added a provenance register documenting the maintainer's no-source-copy assertion, upstream reference categories, required legal review and an explicit release gate. This cannot replace human/legal review, so `ART-LICENSE-001` is not marked complete.

### Validation

- Baseline before batch: `python -m pytest -q` — **186 passed, 1 skipped, 11 subtests passed**.
- Focused integration tests: **11 passed**.
- The two adapter requirements moved from `NOT_STARTED` to `IN_PROGRESS`, not `VERIFIED`: isolated scanner execution and live MCP transport are deliberately not enabled in this environment.

### Remaining blockers

- The environment has no verified container runtime/network namespace/firewall integration; `ART-ISOLATION-001/002` and runtime end-to-end items cannot be honestly closed here.
- Scanner adapters need real pinned images, a worker wrapper, enforced timeout/kill behavior, bounded output collection, SARIF/JSON ingestion and isolated integration tests.
- MCP/skill adapters need a transport that runs inside the isolated worker and can be forcibly terminated at the declared deadline.
- `ART-LICENSE-001` needs a qualified human/legal review and documented decision.
- Verification coverage for scenario/workflow/SARIF findings, transparent traffic capture, and a provenance-backed real scanner benchmark remain incomplete.


## Batch 2.2.19 — close traffic-reference gaps and expand deterministic retesting

**Date:** 2026-10-24  
**Version:** 2.2.19  
**Requirements advanced:** `ART-TRAFFIC-001`, `ART-VERIFY-001`, `ART-BENCH-002`.

### Implemented

- `EvidenceStore.verify_traffic()` now checks the finding→traffic→evidence relationship in addition to traffic↔evidence integrity. Unknown traffic IDs, malformed finding references and a valid traffic ID bound to unrelated evidence fail verification. `EvidenceStore.finding()` rejects explicit traffic links without matching persisted evidence.
- Scenario HTTP status assertion failures preserve a minimal bounded verification contract for `status_equals`, `status_not_equals` and `status_in`. `scenario_status_recheck` uses independently persisted retest status and exact target/evidence linkage; unsupported assertion types return inconclusive rather than guessing.
- Benchmark baseline comparison now requires `measured_baseline=true` and provenance fields for source, collection time, corpus hash and scanner versions. This makes an untraceable baseline invalid, but does not prove that provenance is truthful; real scanner runs and CI integration are still required.

### Validation

- Focused evidence/scenario tests: **23 passed** before the final baseline change; benchmark tests: **7 passed**.
- Full-suite and clean-release validation will be recorded after packaging this batch.

### Remaining blockers

- `ART-TRAFFIC-001`: no transparent capture proxy, and full binary/raw payload capture remains intentionally absent.
- `ART-VERIFY-001`: workflow invariants are review-only and SARIF imports do not carry independent target evidence; they are not automatically promoted to verified findings.
- `ART-BENCH-002`: no actual scanner was run in the isolated worker, so the repository still has no real measured baseline or CI job.


## Batch 2.2.20 — planner prompt-injection boundary tests

**Date:** 2026-10-24  
**Version:** 2.2.20  
**Requirement advanced:** `ART-AUTH-004`.

- Added a hostile-model fixture whose target-derived content attempts to add an external URL, request a destructive method and select an unregistered shell tool. The planner discards unregistered test IDs and emits only registered test IDs plus bounded rationale; it does not accept model-generated URLs, methods or arguments as executable actions.
- `safe_observation` keeps raw response bodies/private fields out of the model payload. Planner-generated reasons and summaries now strip embedded URLs and control characters before downstream persistence.
- Focused adversarial test passes. `ART-AUTH-004` remains in progress because this is not a live hosted-model test, and the legacy engine still is not routed through the queue's exact-action approval ledger.


## Batch 2.2.21 — queue cancellation callback integration

**Date:** 2026-10-24  
**Version:** 2.2.21  
**Requirement advanced:** `ART-RUNTIME-014`.

- Added an integration regression that creates a valid approved action, authorizes it, simulates the durable running state, then calls `RuntimeStore.cancel_job()`. It asserts the registered supervisor receives the exact execution ID and the execution is persisted as cancelled only after the callback returns confirmed termination.
- Focused dispatcher tests: **6 passed**. The fake supervisor proves callback registration and durable transaction wiring only; it cannot prove Docker/Podman process/container termination. `ART-RUNTIME-014` remains `IN_PROGRESS`.


## Batch 2.2.22 — scoped scanner plans and sensitive capability approvals

**Date:** 2026-10-24  
**Version:** 2.2.22  
**Requirements advanced:** `ART-INT-002`, `ART-INT-003`, with scope/approval defense in depth.

- Scanner adapter planning now requires the current assessment policy and validates the URL against ARTEMIS's existing allowlisted host, port, method and path policy without performing DNS/network access. Plans include assessment ID and canonical policy digest and have a stable payload hash. Fixed scanner entrypoints must be absolute.
- MCP/skill capabilities with `write`, `network`, `filesystem` or `secrets` permissions now require a configured trusted approval verifier and matching approval ID after the input schema has passed validation. Sensitive capabilities cannot be authorized by the supplied permission set alone.
- Focused integration tests cover scope rejection, policy binding and exact-action approval matching. These are still adapter contracts only: no scanner image or isolated transport is configured, so execution remains disabled/unsupported.


## Batch 2.2.23 — MCP/skill invocation audit gate

**Date:** 2026-10-24  
**Version:** 2.2.23  
**Requirement advanced:** `ART-INT-003`.

- MCP/skill capability invocation records metadata-only start and completion events with permission list, exact approval reference for sensitive calls, bounded byte counts, elapsed time and SHA-256 hashes. Raw arguments/results are excluded from audit metadata.
- Sensitive capabilities require a configured durable audit sink before invoking their transport. Audit sink failure before execution prevents transport invocation; failure to persist completion causes the caller to receive an error instead of an untracked result.
- Focused integration tests: **14 passed**. This remains partial: the registry is not wired to the SQLite runtime audit chain or a real isolated MCP transport, and hard timeout cancellation remains a transport integration requirement.


## Batch 2.2.24 — scanner output contract

**Date:** 2026-10-24  
**Version:** 2.2.24  
**Requirement advanced:** `ART-INT-002`.

- Added bounded scanner-result validation for exit code, elapsed time, combined output cap and stdout/stderr hashes. Raw scanner output is not returned in metadata. JSON objects/arrays are recognized; SARIF 2.0.0/2.1.0 is accepted only with a basic valid root/runs structure and result count.
- Nonzero exit codes remain explicit `scanner_failed` states; the adapter does not guess scanner-specific meanings. Malformed/oversized SARIF and oversized output fail closed.
- Focused integration tests: **16 passed**. The adapter still cannot execute scanners or ingest findings into the evidence/finding lifecycle without the verified isolated worker and actual scanner images.


## Batch 2.2.25 — CI regression gate

**Date:** 2026-10-24  
**Version:** 2.2.25  
**Requirements advanced:** general regression safety; partial `ART-BENCH-002` operationalization.

- Added `.github/workflows/ci.yml` for Python 3.11 and 3.12. It installs declared dependencies and pytest, compiles the source/tests, runs the full test suite, validates version/catalog, and asserts the offline dry run reports zero network requests.
- Workflow permissions are read-only and it does not scan targets. No GitHub push or remote workflow run was performed from this environment.
- This does not supply a real scanner benchmark or prove that the workflow passes on GitHub-hosted runners; `ART-BENCH-002` remains `IN_PROGRESS`.


## Batch 2.2.26 — legacy inline action digest

**Date:** 2026-10-24  
**Version:** 2.2.26  
**Requirement advanced:** `ART-AUTH-001`, `ART-AUTH-004`.

- Inline authorization now computes a canonical action digest that binds the assessment ID, policy digest, exact URL and method, authentication-profile identifier, body presence and a SHA-256 digest of caller-supplied header values. Only digests/profile identifiers enter audit events; header values are not persisted.
- Authentication profile identifiers are constrained to `default`, `anonymous`, `None`, or bounded `LAB_TOKEN_*` / `LAB_COOKIE_*` names. `LabHTTPClient` verifies the authorization result still matches the request's policy digest and auth profile before proceeding to the transport gate.
- Focused authorization/local HTTP tests: **34 passed** before the final test run; full suite: **210 passed, 1 skipped, 11 subtests passed**. Exact-action queue approvals and verified worker isolation are still not integrated into the legacy engine.


## Batch 2.2.27 — acceptance-criteria status reconciliation

**Date:** 2026-10-24  
**Version:** 2.2.27

- Re-reviewed `ART-AUTH-002`, `ART-AUTH-003` and `ART-TRAFFIC-001` against their stated acceptance criteria and tests. Exact approval lifecycle, closed-world schema gating, and client-level traffic/evidence integrity are now `VERIFIED` within their scoped criteria.
- Split transparent isolated-worker capture into new `ART-TRAFFIC-002` rather than leaving a verified client-level traffic integrity requirement marked incomplete because a different capture mode is missing. The CONNECT broker remains unconnected to an enforced worker route.
- Register now has 93 requirements: **81 VERIFIED, 12 IN_PROGRESS, 0 NOT_STARTED**. This is a status reconciliation, not a claim of production readiness; `ART-AUTH-001`, `ART-AUTH-004`, runtime/isolation, scanner/MCP execution, scenario/SARIF verification, real benchmark and legal review remain open.


## Batch 2.2.28 — verification requirement scope split

**Date:** 2026-10-24  
**Version:** 2.2.28

- Reconciled `ART-VERIFY-001` to the deterministic finding types with positive/negative and restart-recovery coverage, then marked it `VERIFIED`. Existing fixed checks and the bounded scenario status retester satisfy this scoped acceptance.
- Added `ART-VERIFY-003` for unfinished workflow-invariant and SARIF-import verification. Those classes remain review-only until independent evidence and class-specific deterministic checkers exist; they are not treated as automatically verified.
- Requirements register now reports **94 total: 82 VERIFIED, 12 IN_PROGRESS, 0 NOT_STARTED**. This does not close the execution, isolation, benchmark or legal blockers.


## Batch 2.2.29 — prompt-injection requirement scope split

**Date:** 2026-10-24  
**Version:** 2.2.29

- Marked `ART-AUTH-004` verified for its scoped acceptance criteria based on the hostile-model planner test and the legacy HTTP request authorization tests. The planner accepts only registered test IDs, has no model-controlled URL/method/argument field, removes URLs from generated rationale, and the request gate binds action digest while rejecting routing/auth/method overrides. Queue exact-action approval is independently enforced and tested.
- Added `ART-AUTH-004b` for remaining hosted-provider and multi-format adversarial coverage (OpenAPI, SARIF, scenario text and end-to-end queue dispatch). No claim is made that the entire prompt-injection threat surface is exhausted.
- Requirements register now reports **95 total: 83 VERIFIED, 12 IN_PROGRESS, 0 NOT_STARTED**.


## Batch 2.2.30 — real-runtime verification harness and dependency-license inventory

**Date:** 2026-10-24  
**Baseline:** clean extraction of `ARTEMIS-appsec-2.2.29.zip`; no Git metadata exists in the release artifact.  
**Requirements advanced:** evidence and reproducibility improvements for `ART-RUNTIME-013/014`, `ART-ISOLATION-001/002`, `ART-LICENSE-001`; no parent requirement is marked VERIFIED by this batch.

- Added `scripts/real-runtime-preflight.py`, a read-only report of runtime availability, cgroup v2, effective capabilities, network namespace creation, iproute2 and nftables. It has a strict gate exit code for a host missing prerequisites.
- Replaced the old manual-runtime-only integration test with opt-in tests that call the actual `ContainerWorkerSupervisor` against a digest-pinned local fixture. Checks include real container UID/capabilities/NoNewPrivs/read-only filesystem/tmpfs/cgroup ceilings/direct IPv4+IPv6 socket denial, timeout cleanup, cancellation, container absence and rejection of cancelled completion.
- Added `tests/fixtures/worker` and `docs/implementation/runtime-verification.md` with exact test classes, commands, setup steps, skip policy, evidence requirements and safety limits. No public or production target is contacted.
- Added `docs/implementation/license-review-2026-10-24.md` and `dependency-license-inventory.json` documenting observed direct/transitive dependency license metadata, test-only tools, fixture base-image provenance, upstream references, notice obligations and unresolved human/legal review. `ART-LICENSE-001` remains open.
- Added malicious OpenAPI and SARIF fixtures to verify that external descriptions/results remain untrusted inventory/candidate data and cannot directly trigger requests or commands. This improves format-boundary evidence but does not replace live hosted-provider or queue-to-worker adversarial tests.
- Baseline discrepancy: clean v2.2.28 and v2.2.29 both reproduce 210 passed, 1 skipped, 11 subtests passed; the earlier 208-passed statement cannot be reproduced from either available artifact. The opt-in integration test is skipped, not counted as passed.
- Host preflight: Python 3.13.5, Linux kernel 6.18.55, cgroup v2 present, UID 0 but restricted effective capabilities; Docker/Podman and nftables absent; `unshare -n true` exits 1 with `Operation not permitted`. `full_isolation_gate=false`.
- Test command `python -m pytest -q --disable-warnings --maxfail=1`: **214 passed, 3 skipped, 11 subtests passed**; the three skips are opt-in real-container integration tests, not passes. `python -m compileall -q appsec_agent tests agent.py artemis.py scripts/real-runtime-preflight.py` passed. The offline dry run reports zero network requests.
- No firewall rules were applied. No scanner or MCP transport was enabled. Queue dispatch still fails closed before network-required worker actions because the trusted egress/evidence boundary is not configured.

**Remaining blocker:** run the opt-in integration suite on a disposable Linux VM with a supported container runtime, digest-pinned local fixture, namespace privileges and nftables. Even a passing fixture suite will not by itself close end-to-end queue authorization, scoped broker egress, transparent capture, real scanner benchmark, or legal review.
