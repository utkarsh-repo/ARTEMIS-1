# Changelog

## 2.2.30

- Added a read-only real-runtime preflight that records container-runtime availability, cgroup v2, effective capabilities, network-namespace creation, `iproute2`, and nftables readiness without changing host state.
- Reworked opt-in real-container tests to exercise `ContainerWorkerSupervisor.run()` and `.cancel()` against a digest-pinned local worker fixture. The suite checks non-root execution, zero effective capabilities, `NoNewPrivs`, read-only root filesystem, tmpfs, cgroup memory/CPU/PID ceilings, direct IPv4/IPv6 socket denial, timeout cleanup, cancellation, and absence of a cancelled completion result.
- Documented distinct unit, fake-runtime, real-container, network-isolation, and end-to-end test classes with a reproducible disposable-Linux setup and explicit no-public-target policy.
- Added a technical dependency/license inventory in Markdown and JSON for observed runtime and test dependencies, upstream provenance references, notice preservation, and open legal-review decisions. Added hostile OpenAPI and SARIF fixtures confirming external content remains inventory/candidate data rather than an execution instruction. `ART-LICENSE-001` remains `IN_PROGRESS`; this is not a legal determination.
- Baseline validation found 210 passed, 1 skipped, and 11 subtests passed for both the available clean 2.2.28 and 2.2.29 extractions. The previously reported 208-passed figure is not reproducible and is recorded as a reporting discrepancy.
- Full local suite after the new format-boundary and preflight tests: 214 passed, 3 opt-in real-runtime tests skipped, 11 subtests passed. No critical runtime requirement is marked VERIFIED from code scaffolding alone. The actual container/namespace/firewall tests remain opt-in and are skipped on this host because Docker/Podman, nftables, and namespace privileges are unavailable.


## 2.2.29

- Reconciled `ART-AUTH-004` as verified for the tested planner/request boundary: hostile model output cannot add unregistered test IDs or turn target-provided URLs into action parameters, and the inline request gate rejects routing/authentication/method overrides.
- Added `ART-AUTH-004b` for remaining multi-format and hosted-provider prompt-injection coverage, including OpenAPI/SARIF/scenario inputs and end-to-end queue integration.
- Requirements register now lists 95 requirements: 83 verified, 12 in progress. This is acceptance-criteria bookkeeping; it does not change the real-worker isolation blocker.

## 2.2.28

- Reconciled `ART-VERIFY-001` as verified for the deterministic finding classes it explicitly supports, including the new bounded scenario status retester and restart replay tests.
- Split unfinished workflow-invariant and SARIF-import verification into `ART-VERIFY-003`. These finding classes remain review-only until class-specific independent evidence adapters are implemented; no unsupported finding is promoted.
- Requirements register now lists 94 requirements: 82 verified and 12 in progress. Counts remain an engineering checklist, not a readiness or autonomy score.

## 2.2.27

- Reconciled requirement status against acceptance criteria and test evidence: `ART-AUTH-002`, `ART-AUTH-003` and `ART-TRAFFIC-001` are now `VERIFIED` for their explicitly scoped authorization-gate and client-level traffic-integrity criteria.
- Added `ART-TRAFFIC-002` to track the distinct unfinished capability of forcing isolated-worker HTTP traffic through a capture boundary. The CONNECT broker exists, but worker-network enforcement is not wired or verified.
- Updated the register snapshot to 93 requirements: 81 verified, 12 in progress, 0 not started. These counts describe requirement status, not production readiness; real handler execution remains blocked by the isolation requirements.

## 2.2.26

- Strengthened the legacy inline request authorization decision to bind a canonical action digest to assessment/policy, exact URL and method, authentication-profile identifier, body presence and a SHA-256 digest of caller-supplied headers.
- Authorization events expose the digest and header hash, never raw header values. Authentication-profile identifiers are constrained to explicit built-in values or strict `LAB_TOKEN_*` / `LAB_COOKIE_*` names.
- `LabHTTPClient` now checks that the authorization result's policy digest and auth profile still match before transport. Added regressions proving header-value/auth-profile substitutions change the action digest and invalid auth profile names are rejected.
- `ART-AUTH-001` remains `IN_PROGRESS`: legacy decisions are now more precisely bound, but they still do not use the queue's approval ledger or a real isolated execution boundary.

## 2.2.25

- Added a GitHub Actions regression workflow for Python 3.11/3.12, compilation, the full test suite, CLI/catalog validation and an offline dry run asserting zero network requests.
- The workflow has read-only repository permissions and does not execute scanner tasks or send traffic to assessment targets.
- This adds general CI regression coverage, not the missing measured scanner benchmark. `ART-BENCH-002` remains `IN_PROGRESS` until an isolated real scanner baseline and controlled comparative run are available.

## 2.2.24

- Added bounded scanner-result validation that records exact exit code, elapsed time, byte counts and SHA-256 hashes without returning raw stdout/stderr. Recognizes JSON arrays/objects and validates basic SARIF 2.0.0/2.1.0 structure and result counts.
- Invalid or oversized SARIF and combined stdout/stderr output over the adapter cap are rejected. Nonzero exit codes are preserved as scanner failures; no scanner-specific meaning is guessed.
- Added tests for valid SARIF metadata, nonzero exit status, secret-safe output summaries, invalid SARIF and output-cap enforcement. Real scanner execution remains disabled pending pinned images and verified isolation.

## 2.2.23

- MCP/skill invocation now emits metadata-only start/completion audit events with argument/result SHA-256 digests and bounded byte counts; raw arguments and results are not placed in audit events.
- Sensitive capabilities now require a configured durable audit sink before transport invocation. If audit persistence fails before execution, the transport is not called; post-execution audit failure raises a fail-closed recovery error rather than returning an untracked result.
- Added tests for audit metadata redaction, durable sink requirements and preventing a sensitive transport from running without audit persistence. The registry is still not connected to the runtime store/isolated worker.

## 2.2.22

- Scanner adapter planning now requires a non-empty assessment policy, validates the target with ARTEMIS's existing host/port/method/path policy before generating a plan, and binds the plan to the assessment ID and canonical policy digest. Scanner entrypoints must be absolute fixed paths.
- MCP/skill capability definitions now identify sensitive permission sets (`write`, `network`, `filesystem`, `secrets`) as approval-required. Invocations require a trusted exact-action approval verifier and approval ID after argument-schema validation; arbitrary caller permission sets alone cannot authorize sensitive capabilities.
- Added tests for out-of-scope scanner targets, assessment/policy binding, absolute entrypoints, and sensitive MCP approval matching. Scanner/MCP execution remains gated on the isolated worker integration.

## 2.2.21

- Added a queue/runtime integration regression that creates an authorized execution in the durable `running` state, invokes `RuntimeStore.cancel_job`, verifies the registered supervisor callback receives the exact execution ID, and confirms durable execution state changes to `cancelled` only after the callback reports termination.
- The integration uses a fake supervisor because Docker/Podman are unavailable; it verifies callback wiring and transaction semantics, not real container termination. `ART-RUNTIME-014` and `ART-ISOLATION-001` remain `IN_PROGRESS` pending a real runtime test.

## 2.2.20

- Added adversarial planner tests where target response content attempts to add a new target, request DELETE, and invoke an unregistered shell tool. Planner output remains limited to registered test IDs; private/raw observation fields are excluded from the model payload.
- Bounded and sanitized model-generated planner reasons and summaries, removing embedded URLs and control characters before they can enter downstream planner state.
- `ART-AUTH-004` remains `IN_PROGRESS`: the new tests exercise deterministic planner boundary handling, but a full hosted-model adversarial integration suite and queue-bound legacy-engine authorization are still open.

## 2.2.19

- Tightened traffic journal verification to validate finding → traffic → evidence edges, reject unknown/tampered traffic references, and reject attaching a valid but unrelated traffic ID to a finding.
- Added independent, evidence-bound retesting for scenario HTTP status assertions (`status_equals`, `status_not_equals`, `status_in`). Scenario findings now retain only bounded status assertion metadata; unsupported assertion types remain inconclusive.
- Benchmark comparisons now require `measured_baseline=true` plus provenance metadata (`source`, collection timestamp, corpus SHA-256 and scanner versions), reducing the risk of comparing against an untraceable baseline. Synthetic fixtures are still not a real scanner baseline.
- Added regression tests for finding-link tampering, unrelated evidence links, scenario retest outcomes, unsupported assertion types and missing benchmark provenance.
- `ART-TRAFFIC-001`, `ART-VERIFY-001` and `ART-BENCH-002` remain `IN_PROGRESS`: transparent proxy capture, broader scenario/workflow/SARIF verification, and a real isolated scanner baseline/CI wiring are not available yet.

## 2.2.18

- Added `appsec_agent/integrations.py` with closed-world scanner adapter definitions and bounded invocation-plan generation for Nuclei, ZAP Baseline and Trivy Config. Plans never execute in-process; scanner execution remains disabled until a real pinned image and verified worker integration are configured. No fake image digest is treated as trusted.
- Added explicit MCP/skill capability registration with declared permissions, JSON object schemas, required fields, no additional properties, input/output byte caps, timeout metadata, and machine-readable invocation metadata. The transport remains operator-supplied and must enforce hard timeout/cancellation inside the verified worker before production use.
- Added 11 integration tests covering unknown adapters, unsafe targets, resource bounds, digest validation, missing permissions, unknown fields, bad types and output caps.
- Added `docs/implementation/provenance-register.md` to document source provenance assertions and unresolved legal review. `ART-LICENSE-001` remains open pending a human/legal decision.
- `ART-INT-002` and `ART-INT-003` advanced from `NOT_STARTED` to `IN_PROGRESS`; they are not marked complete because neither adapter family is wired to a verified isolated executor.

## 2.2.17

- Hardened SARIF import as an untrusted-input boundary: support only SARIF 2.0.0/2.1.0, reject symlink/non-regular and oversized files, read at most 10 MiB, bound runs/rules/results/text/tags, skip malformed individual records with redacted reason-code events, and count only newly persisted findings.
- Added SARIF regression tests for valid imports, severity mapping, malformed records, unsupported versions, non-object roots, oversized files, symlink rejection, bounded text/URI/tags and duplicate imports.
- `ART-INT-001` remains an import-only capability; this release does not add or execute scanner adapters.

## 2.2.16

- Hardened the legacy read-only HTTP authorization boundary against scope/routing and method-semantic overrides: reject Host/authority, credential, proxy, transport, forwarding and method-override headers; reject CRLF/NUL and malformed/oversized header maps; reject bodies for GET/HEAD/OPTIONS; validate auth-profile identifiers before transport.
- Added adversarial gateway and local-client regression tests proving rejected overrides fail before any HTTP session/transport is invoked and secret header values are not included in authorization audit events.
- `ART-AUTH-004` remains `IN_PROGRESS`: these controls reduce request-level bypass paths but do not complete prompt-injection end-to-end validation or queue-bound exact-action authorization for the legacy engine.

## 2.2.15

- Added `--benchmark-compare` for CI-friendly comparison of current benchmark metrics against a named baseline and explicit precision/recall/F1 and runtime/request/cost thresholds.
- CLI comparison rejects symlink/non-regular/oversized input files, emits machine-readable JSON and exits with status 2 on invalid input or regression.
- Added `docs/operations/benchmark-regressions.md` with the input schema and CI integration guidance. `ART-BENCH-002` remains `IN_PROGRESS` until a provenance-backed real scanner baseline and automated CI workflow exist.


## 2.2.14

- Added deterministic retest checks for cookie security attributes, risky advertised HTTP methods and anonymous authentication boundaries. Cookie evidence persists only boolean attribute observations, not cookie values.
- Persisted verification decisions now reconcile into matching blackboard claims: corroborated results may mark a claim verified only with original and retest evidence; negative/inconclusive results map to `inconclusive`. Restart reconciliation replays durable verification history after interrupted claim updates.
- Added strict benchmark baseline comparison for precision/recall/F1 regression deltas and runtime/request/model-cost increases, requiring a named baseline and explicit threshold values.
- Added tests for the new verifier classes, evidence redaction, automatic claim promotion, crash/restart replay and benchmark threshold violations. Added a three-case synthetic planner-coverage benchmark that verifies unseen-category ranking beats a priority-only baseline.
- `ART-PLAN-002` is verified against a synthetic three-case coverage benchmark; this is not a real scanner benchmark.
- **Still incomplete:** verification for scenario/workflow/SARIF-derived finding classes and a provenance-backed real scanner benchmark baseline remain open. No real scanner was run.


## 2.2.13

- Expanded the same-origin loopback dashboard to list persisted assessments and approvals and inspect findings, assets, claims, events and traffic records.
- Added UI controls for approval decision/rejection and revocation, backed by existing server-side approver/admin role checks; dashboard state is rendered using `textContent` and no third-party scripts are loaded.
- Added bounded assessment-file reads, symlink/path checks, recursive secret/URL redaction and sanitized job/task outputs; runtime API now lists approvals without exposing action parameters.
- Added API integration coverage for assessment and approval views, query-secret redaction, sensitive task payload omission, CSP and dashboard controls. `ART-UI-001` is now verified for the documented local-only scope.
- Remote TLS/identity-provider integration remains out of scope; dashboard binds only through the existing loopback API.


## 2.2.12

- Added a manifest-backed `traffic.jsonl` exchange journal with unique traffic IDs, request/response metadata and body hashes. Completed HTTP responses and transport failures are recorded with redacted headers/URLs; findings automatically inherit traffic IDs from persisted evidence IDs.
- Added `EvidenceStore.verify_traffic()` and `--verify-traffic` to verify traffic/evidence/finding references alongside the evidence manifest. Evidence sequence recovery prevents ordinary restart collisions.
- Added a same-origin loopback operator dashboard served by the authenticated control API. It reads persisted health/jobs/task states and can request job cancellation; server-side role checks remain authoritative. Job/task API output now omits raw task inputs and results.
- Added local HTTP/evidence tests for traffic ID linkage, secret redaction, restart uniqueness, tampered references and dashboard API sanitization.
- **Still incomplete:** this is client-level redacted traffic capture, not a transparent proxy or raw/binary capture; the dashboard does not yet cover findings/assets/logs/approvals. `ART-TRAFFIC-001` and `ART-UI-001` are `IN_PROGRESS`, not verified.


## 2.2.11

- Added `appsec_agent/budget.py`, a durable per-assessment hosted-model budget ledger with pre-call reservations for request count, conservative input-token allowance, bounded output tokens, cumulative tokens and configured USD cost.
- Hosted providers now require explicit `llm_budget` configuration whose provider/model exactly matches the effective API model; invalid or missing budget config is rejected before assessment target requests begin.
- OpenAI/Anthropic calls receive the configured output cap, provider usage is settled into the ledger, and usage overruns persist a budget-exhausted state that prevents subsequent hosted calls. Budget exhaustion stops planner selection instead of falling back to another model call.
- Added nine budget tests for reservation persistence, request/token/cost caps, usage settlement and overrun, immutable restart limits, malformed config, model mismatch and planner stop behavior.
- `ART-BUDGET-001` is now verified by tests; this is a local single-process ledger and still relies on the operator to configure accurate model-specific prices. It is not a provider billing guarantee or distributed budget service.


## 2.2.10

- Added `QueueDispatcher` to connect persistent `tool_action` task claiming with `AuthorizationGateway`, immediate pre-execution revalidation, redacted denial handling, and the worker-supervisor cancellation callback.
- Added task-type filtering to `RuntimeStore.claim_next` without changing existing callers; dispatcher cannot accidentally claim unrelated report/planning tasks.
- Added `--runtime-action dispatch-once`. Worker image and fixed entrypoint may be supplied as trusted deployment configuration via `ARTEMIS_WORKER_IMAGE` and `ARTEMIS_WORKER_ENTRYPOINT_JSON`; no task can choose the executable.
- **Still fail-closed:** `AuthorizationGateway.begin_execution` blocks because real container isolation and host-enforced scoped egress are not verified. The dispatcher does not invoke a handler or make network requests in this environment. `http_request` remains unavailable until the worker boundary is actually integrated and verified.


## 2.2.9

- Connected durable job cancellation to registered supervisor cancellation callbacks. A job with a persisted `running` execution cannot be marked cancelled unless a supervisor confirms termination for every running execution; cancellation failures roll back task/job state and record a denial event separately.
- Changed worker container names to stable execution-ID-derived names so a restarted controller can locate a leftover container without persisting host process handles. Cancellation can stop/remove a persisted container and verifies it is absent afterward.
- Added regression tests for cancellation without a supervisor, failed termination, confirmed termination, stable container identity and cleanup after controller restart.
- **Still incomplete:** no queue dispatcher invokes the supervisor for authorized `http_request` tasks; `AuthorizationGateway.begin_execution` remains fail-closed until the isolated network boundary is configured. No actual container runtime or nftables enforcement was available for integration testing.

## 2.2.8

- Added `InlineRequestAuthorizationGateway` to the legacy deterministic HTTP client. Every request now passes a policy-digest and in-scope target gate; legacy execution is restricted to GET/HEAD/OPTIONS, and authorization events omit query strings and credential-bearing values. The transport retains independent URL validation, explicit allowed-port enforcement, connection-time DNS/IP validation, IP pinning, TLS verification, and disabled redirects.
- Added `appsec_agent/scoped_egress.py`: exact host/port CONNECT authorization, live assessment/policy-version revalidation per tunnel, all-answer DNS validation, explicit CIDR exceptions only, signed in-process authorization decisions, pinned-IP sockets, redacted allow/deny events, and a CONNECT-only broker. HTTPS path/method enforcement remains the HTTP client's responsibility.
- Added a dry-run-first nftables rule generator for a dedicated worker subnet. It allows that subnet to reach only the configured broker endpoint and drops other worker-subnet input/forward traffic. Applying firewall rules is explicit and guarded; rules were not applied in this environment.
- Hardened the container supervisor to inspect the local image and verify the exact repository digest before launch, and to force-remove the container and verify the runtime process has exited during termination. Fake-runtime tests cover digest mismatch and cleanup command construction.
- Tightened queued authorization to reject approvals that are no longer in the consumed state or have expired before execution or result commit.
- Added opt-in real Docker/Podman isolation tests and scoped-egress deployment guidance. They are not run by default and require a local digest-pinned worker image and a supported runtime.
- **Still incomplete:** no supported container runtime or privileged network namespace is available in the current environment. Worker network remains disabled; scoped egress is not connected to worker networking, and queue cancellation/dispatch is not connected to the supervisor. Do not mark end-to-end execution, real container isolation, or host egress enforcement VERIFIED.

## 2.2.7

- Added `ContainerWorkerSupervisor` using a fixed operator-configured entrypoint and SHA-256-pinned image; task payloads cannot select executable names or alter runtime arguments.
- Added container controls for `--network=none`, read-only root filesystem, non-root UID/GID, dropped capabilities, no-new-privileges, CPU/memory/PID limits, bounded tmpfs, and `--pull=never` so the runtime does not fetch an image during execution.
- Added bounded JSON input/output, hard wall-clock timeout, active execution tracking, explicit cancellation, container stop and runtime process-group termination, and a strict result/evidence-reference contract.
- Network-capable actions are rejected because no externally enforced scoped egress proxy is configured. No real container runtime is available in this environment; tests use a fake runtime to verify command construction and lifecycle only. The supervisor is not yet wired to the persistent queue or `AuthorizationGateway`, and execution remains blocked.
- Validation: `python -m pytest -q tests/test_worker_supervisor.py` — 10 passed. Full release validation is recorded in `docs/implementation/progress.md`.

## 2.2.6

- Verified the previously `IMPLEMENTED` asset deduplication, bounded trace search and proxy-bypass protections with targeted regressions. Repeated asset sightings now preserve first-seen values and record attribute/scope conflicts.
- Added a chained evidence manifest binding each JSONL row to a record hash; verification detects row mutation, deletion, reordering and unmanifested records. Evidence export includes file hashes, integrity result and a redaction summary.
- Added archive-before-delete evidence retention with dry-run default, an evidence-bound verification/retest history module, and engine-start reconciliation that reopens unsupported prior execution statuses for review.
- Added explainable deterministic planner ranking using priority, risk, category coverage and retry state; model planners receive the score rationale but remain restricted to registered test IDs.
- Added local health metrics and integrity checks, SQLite online backup/restore with schema validation, a sanitized positive/negative benchmark corpus and metric evaluator.
- Added a loopback-only bearer-token operator API with server-side role mapping, bounded request bodies, job health/read/cancel and approval decision/revocation routes; exposed it via `--runtime-action serve-api`.
- **Not complete:** deterministic verification covers only a fixed subset of finding types and does not automatically promote blackboard claims; model cost budget enforcement, real-runtime isolation validation and queue-integrated process/container cancellation, scanner/MCP adapters, full traffic proxy, dashboard, remote identity provider/TLS and legal review remain open.
- Validation: `python -m pytest -q` — 118 passed, 7 subtests passed; compile, catalog, CLI and clean-package checks documented in the implementation journal.

## 2.2.5

- Added `AuthorizationGateway` for queued `tool_action` tasks. It recomputes the current policy digest, revalidates the live lease and job state, validates the registered schema and target scope, verifies exact-action approval and expiry/revocation, and atomically consumes approval with a unique execution authorization record.
- Bound each authorization digest to assessment/job/task identity, scope/policy digest, target and operation, canonical arguments, registered tool version, unique action ID, approval identity and expiry. Replay and post-approval parameter/scope substitution fail closed.
- Added execution-attempt lifecycle records, action-time revalidation, evidence-backed atomic completion, failure/cancellation handling, and `recovery_required` rather than automatic replay after a lease expires after approval consumption. The current gateway deliberately blocks before `running` because no isolated executor is installed.
- Added revocation support and a SHA-256 chained runtime event log with a persisted head; common credential-bearing URL/text values are redacted from audit payloads. The chain detects row edits and tail truncation against the stored head, but is not a defense against an attacker who can rewrite the entire database and its head.
- Added tool version/risk/approval/timeout/response-cap metadata. The timeout is declarative until an isolated worker backend enforces it.
- Added tests for policy changes, parameter substitution, expired/revoked approvals, replay, lease ownership, cancellation, crash recovery, durable evidence completion, audit redaction/integrity and v1/v2 schema migration.
- **Important limitation:** this batch does not add an isolated process/container executor and does not connect the legacy `engine.run` HTTP/scanner loop to queue dispatch. The gateway can authorize and record an execution attempt, but production tool invocation remains blocked pending a trusted isolated backend; do not claim end-to-end dispatch enforcement yet.

## 2.2.4

- Added a closed-world tool registry with strict JSON argument validation and a narrow `http_request` schema limited to GET/HEAD/OPTIONS, configured authentication-profile references, and bounded response bytes.
- Integrated registry validation into approval requests and approval consumption; unknown tool names, unknown parameters, raw arbitrary headers, unsafe methods, and invalid response limits fail closed before approval/consumption.
- Added regression tests for unknown tools, unexpected fields, unsafe methods, bool-as-integer mistakes and bounded parameter values.
- The registry validates approved action descriptors only; it does not execute requests and is not yet wired into a worker/scanner dispatch path.

## 2.2.3

- Added a persistent exact-action approval ledger bound to job, target, tool, exact parameters and canonical policy digest; parameter values are not persisted in approval records.
- Added deterministic policy URL/method scope validation at approval request and consumption, requester/approver separation, expiry handling, one-time atomic consumption, and approval audit events.
- Added CLI operations for approval request, decision, consumption and listing. CLI operator identifiers are bound to the current OS account instead of trusting an arbitrary supplied name.
- Added regression tests for action mutation, cross-job/cross-target reuse, policy mismatch, scope violations, expiry, rejection, replay, concurrency and secret persistence. Approval consumption is not yet connected to scanner or worker execution.


## 2.2.2

- Added a transactional SQLite runtime queue for durable jobs/tasks, canonical policy digests computed from validated policy, digest-checked task claims, idempotent job creation, dependency ordering and cycle rejection, single-winner task leases, lease heartbeats, bounded retries, expired-lease recovery, cancellation, task event audit history, and fail-closed worker lease tokens.
- Exposed the runtime queue through explicit `--runtime-action` CLI commands. Queue management does not itself execute security tools; existing deterministic scope checks remain required at execution time.
- Added concurrency, retry, cancellation, dependency, cycle, permission, and lease-expiry regression tests.


## 2.1
- Added persistent todo items with dependency-aware readiness.
- Added deduplicated finding IDs and a prioritized report summary.
- Added operator hints (`--hint`) to steer planning between runs.
- Added planner registry dispatch for all declared test IDs.
- Added configurable provider base URLs for compatible gateways.
- Expanded automated tests for todos and finding deduplication.
- Kept scope/method enforcement outside the LLM so model output cannot directly issue arbitrary requests.

## 2.1.1
- Rebranded the application as ARTEMIS (Autonomous Application Security Testing Platform).
- Added the `artemis.py` CLI entry point and `--version` flag.
- Updated the primary documentation and command examples to use ARTEMIS.
- Retained `agent.py` as a backwards-compatible entry point.

## 2.2.0
- Upgraded the persistent blackboard schema with backward-compatible migration defaults, atomic writes and fail-closed corrupt-state handling.
- Added first-class claim lifecycle records with provenance, evidence references, explicit verification states and review history.
- Added in-run asset records, structured trace retrieval, graph integrity checks and stricter todo dependency/status validation.
- Integrated baseline/test/planner traces and `pending_verification` claims into the assessment engine.
- Fixed path-prefix boundary matching so `/api` does not authorize `/apix`.
- Added `--validate-state` and initial architecture, parity, threat-model, roadmap and benchmark documentation.
- Added per-test execution status history so deferred or blocked tests are not counted as completed coverage.
- Reports now expose unresolved claim states and per-test coverage gaps rather than implying missing configuration was tested.
- Added integration coverage for end-to-end offline execution, deferred OpenAPI inventory, and report claim lifecycle.


## 2.2.1
- Redacted common secret-bearing fields in captured request/response headers, URLs, structured JSON bodies, and model-safe observations.
- Preserved the SHA-256 of the original response body while storing a redacted representation; binary response bodies are omitted from persisted body content.
- Hardened evidence writes against filename traversal and symlink destinations, and enforce restrictive file permissions plus fsync.
- Tightened policy and URL validation for malformed ports, URL fragments, control characters, backslashes, ambiguous host allowlists, and malformed method/path configuration.
- Bound HTTP(S) socket connections to a freshly resolved and policy-checked IP address while retaining the original hostname for HTTP Host and TLS certificate/SNI validation; proxy routing is rejected because it bypasses this guarantee.
- Added a DNS-rebinding regression test that changes a host from a public IP at preflight to a private IP at connection time and confirms the request is blocked.
- Added regression tests for nested JSON secrets, query-string secrets, symlink writes, path traversal, and ambiguous URL/policy inputs.
