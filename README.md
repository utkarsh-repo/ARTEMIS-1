# ARTEMIS

**Autonomous Application Security Testing Platform**

*Think. Test. Verify.*

ARTEMIS is a modular, response-driven application-security testing platform for **explicitly scoped staging or development deployments**. It combines deterministic checks, a bounded model planner (OpenAI or Anthropic), a persistent fact/intent blackboard, test-scenario execution, OpenAPI inventory, and local evidence/reporting.

ARTEMIS uses architectural ideas inspired by the linked projects—Cairn's fact/intent graph and state-space search, and ARTEX's planning/work separation, captured evidence, and durable task history. It does **not** copy their source code.

References:
- Cairn: https://github.com/oritera/Cairn
- ARTEX: https://github.com/trhhubsd/ARTEX
- OWASP Top 10:2025: https://top10.owasp.org/2025/
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- CWE Top 25:2025: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25

## Standards version note

The catalog targets OWASP Top 10:2025, OWASP API Security Top 10:2023, and CWE Top 25:2025. Use the exact version labels in reports when comparing them with internal compliance requirements.

## What's implemented

### Runtime architecture
- Persistent blackboard with facts, claims, intents, asset anchors, evidence references, test state, execution traces, and run hints. State schema migrations preserve legacy records and corrupted state fails closed.
- OODA-like loop: observe existing facts -> choose a registered test -> execute the test -> store evidence/finding -> replan.
- OpenAI and Anthropic planner adapters; deterministic planner fallback when offline or when a provider call fails. Custom OpenAI-compatible and Anthropic-compatible base URLs are supported.
- AI can choose only registered test IDs. It cannot invent URLs, raw HTTP, headers, methods, bodies, payloads, or credential values.
- Basic local SARIF import to combine results from code scanners. Imported/check-generated findings are tracked as `pending_verification` claims, not automatically treated as independently verified vulnerabilities.

### Authorization gateway and durable runtime queue (v2.2.5–v2.2.6)
- A separate SQLite job/task queue supports idempotent job creation bound to a policy digest, dependency-aware task ordering, exclusive worker leases, lease heartbeats, bounded retries, expired-lease recovery, cancellation, and ordered lifecycle events.
- `AuthorizationGateway` now authorizes claimed `tool_action` tasks against the current validated policy, exact approval, fixed tool schema/version, target/method scope, live lease and unique action ID. Authorization and approval consumption are committed together; expiry, revocation, policy changes, parameter substitution and replay fail closed.
- `QueueDispatcher` and `--runtime-action dispatch-once` now connect persistent tool-action claiming to the authorization gateway and register supervisor cancellation. The dispatcher claims only `tool_action` tasks and remains fail-closed before handler invocation until real worker isolation and host-enforced scoped egress are verified.
- Execution-attempt records model authorization/running/completion/failure/cancellation/block/recovery-required states. The gateway currently blocks before `running` because no isolated supervisor can attest to resource, filesystem and egress controls. Its completion contract requires a durable evidence record matching the action ID, target and operation. Runtime audit events are redacted and hash-chained with a stored head; this is tamper-evident against row edits/truncation, not against an attacker who can rewrite the entire database.
- **Not yet end-to-end:** there is no trusted isolated process/container executor, and the legacy assessment engine is not wired to queue dispatch. The loopback-only authenticated operator API is available via `--runtime-action serve-api`; it uses server-side bearer-token/role configuration, has no remote identity provider or TLS, and refuses non-loopback binds. The gateway's `authorized` record is not proof that a tool ran. No production execution is claimed until the worker supervisor and egress boundary are implemented and tested.
- SQLite is intended for a single host. Multi-host workers require a transactional PostgreSQL backend and an execution supervisor.

### Evidence integrity and operations (v2.2.6)
- JSONL evidence, finding and event rows are bound to a chained manifest; `EvidenceStore.verify_manifest()` detects record changes, deletion and missing manifest entries. This is local tamper evidence, not protection against a privileged attacker who can rewrite both data and manifest.
- Evidence export verifies integrity and includes per-file hashes plus a redaction summary. `EvidenceRetentionManager` defaults to dry-run and archives a verified run before deleting it when explicitly enabled.
- Assessment startup reconciles prior executed statuses against durable facts/evidence and marks unsupported results stale for review. A separate append-only retest history preserves prior findings.
- Local runtime health and SQLite online backup/restore helpers validate integrity and restrictive file permissions. A sanitized benchmark corpus and metric evaluator are included; a real scanner baseline is not yet established.
- The operator API is loopback-only. Example server-side credential configuration is provided in `docs/operations/operator-api.md`; never put bearer tokens in source control or command-line arguments.

### Runtime HTTP checks
- HTTPS-by-default, exact host allowlist, path-prefix scope, optional controlled private staging, DNS resolution guard.
- GET/HEAD/OPTIONS by default; state-changing methods blocked unless both policy and a run-level acknowledgement enable them.
- Request budget, per-request pacing, response size cap, timeout, TLS verification, and redirects disabled.
- Security headers, cookie flags, server/framework disclosure, cache policy, content-type/nosniff hints, CORS preflight behavior, HTTP OPTIONS/method exposure, and error-surface review.
- Optional anonymous-vs-authenticated checks on explicitly configured read-only paths.
- Optional OpenAPI inventory and bounded GET smoke checks for in-scope, concrete GET paths.

### Application-specific scenarios
- JSON-authored scenarios for role/object-access comparisons, API property/authorization checks, and business workflow invariants.
- Scenario steps are authored by the application team, not generated by the model.
- Every step must pass the same policy gate.
- State-changing steps require policy opt-in, run-level acknowledgement, disposable test data, and a cleanup sequence.
- Assertions: status in set, status equality/inequality, JSON-path equality/in-set, body-not-contains, and response equality checks.
- Workflow definitions can describe expected states/transitions and invariants for payment and account flows.

### Coverage and reporting
- Current OWASP Top 10:2025 map, OWASP API Security Top 10 (2023) map, CWE Top 25 (2025) map, and business-logic checklist.
- Coverage distinguishes executed, partially executed, deferred, blocked, failed, stale, review-only, external-tool-required, and manual-review-required states. Missing configuration is never counted as executed coverage.
- JSONL evidence and findings, persistent `blackboard.json`, `coverage.json`, `graph_validation.json`, `run_summary.json`, and a Markdown report with claim lifecycle and unresolved questions.
- Local evidence preserves request/response detail. Credentials are excluded from model context and redacted in report summaries. Evidence files may contain secrets and must be treated as sensitive.

## What is not honestly claimed

No black-box agent can prove complete coverage of every OWASP/CWE class with generic HTTP requests. For full assurance, add source-code/SAST, SCA/SBOM, runtime instrumentation, authorized log/alert checks, and app-specific scenarios. The CWE Top 25 includes memory-safety and code-level weaknesses that cannot be comprehensively detected over HTTP alone. ARTEMIS records those gaps rather than marking them as passed.

The stateful scenario runner is a framework, not a universal payment exploit suite. It needs your API paths, test identities, seeded object IDs, expected access matrix, and business invariants to make meaningful assertions.

## Runtime queue CLI (management only)

```bash
# Create a queue job. ARTEMIS validates the policy and computes its canonical digest.
python artemis.py --runtime-db runs/runtime.sqlite3 --runtime-action create-job \
  --policy policy.example.json --idempotency-key assessment-2026-q4

# Add a registered task descriptor to the returned job ID.
python artemis.py --runtime-db runs/runtime.sqlite3 --runtime-action add-task \
  --job-id JOB_ID --task-key baseline --task-type baseline --task-input '{"profile":"staging-baseline"}'

# Claim only if the validated policy digest matches the job; returns a lease token.
python artemis.py --runtime-db runs/runtime.sqlite3 --runtime-action claim \
  --policy policy.example.json --job-id JOB_ID --worker-id local-worker-1

# Inspect persisted queue state; other actions include start, heartbeat, complete,
# fail, cancel, recover, and events.
python artemis.py --runtime-db runs/runtime.sqlite3 --runtime-action status --job-id JOB_ID
```

The CLI computes the digest from the validated policy file and requires the same digest at claim time. The approval commands bind an action to an assessment and a policy snapshot. Approval requests and consumption are checked against a closed-world tool registry; the current `http_request` descriptor only permits GET/HEAD/OPTIONS, an optional configured authentication-profile identifier, and a bounded response size. Arbitrary headers, bodies, shell commands, and unregistered tool names are rejected:

```bash
# Create an approval request (uses the current OS account as requester)
python artemis.py --runtime-db runs/runtime.sqlite3 --runtime-action approval-request \
  --policy policy.example.json --job-id JOB_ID \
  --action-target https://staging.example.test/api/health --tool-name http_request \
  --action-parameters '{"method":"GET"}'

# A different OS account must decide; the request ID comes from the first command
python artemis.py --runtime-db runs/runtime.sqlite3 --runtime-action approval-decide \
  --approval-id APPROVAL_ID --approval-decision approve --approval-reason "Scope reviewed"

# Consume the approval with the exact same action tuple
python artemis.py --runtime-db runs/runtime.sqlite3 --runtime-action approval-consume \
  --policy policy.example.json --job-id JOB_ID --approval-id APPROVAL_ID \
  --action-target https://staging.example.test/api/health --tool-name http_request \
  --action-parameters '{"method":"GET"}'
```

**Important:** consumption is a tested primitive but is not yet connected to an actual scanner/worker dispatch path. Queue claiming is not a full authorization gateway: authenticated operator API, action-time connection authorization, and isolated worker execution remain open. The current fixed tool schema is enforced for approval requests/consumption but is not yet called by an actual worker dispatch path. The runtime DB is private to its creating OS account by default, so a second account cannot decide the request unless shared access is deliberately configured; do not weaken database permissions casually. The CLI derives actor identity from the OS account, but this is not a replacement for an authenticated multi-user API. Do not place credentials in task inputs; common secret-bearing fields are redacted on persistence.

## Setup (macOS / Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp policy.example.json policy.json
```

Edit `policy.json` to specify **your exact staging hostname** and allowed path prefixes. Wildcards are forbidden.

### Configure the AI provider

OpenAI:
```bash
export AI_PROVIDER=openai
export OPENAI_API_KEY='...'
export OPENAI_MODEL='gpt-6-luna'
```

Anthropic:
```bash
export AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY='...'
export ANTHROPIC_MODEL='claude-sonnet-5'
```

Provider model IDs change over time; these defaults are examples and can be overridden with `OPENAI_MODEL` / `ANTHROPIC_MODEL`. Check the providers' current model pages before deployment.

Offline mode does not call an LLM:
```bash
export AI_PROVIDER=offline
```

### Local credentials

Use dedicated test identities. Example:
```bash
export LAB_BEARER_TOKEN='dedicated-test-token'
export LAB_TOKEN_USER_A='user-a-test-token'
export LAB_TOKEN_USER_B='user-b-test-token'
```

Tokens are loaded only by the local runner. The planner gets sanitized observations, not cookies or tokens.

### Validate before running

```bash
python artemis.py --policy policy.json --dry-run
python -m unittest discover -s tests -v
```

### Run a bounded test

```bash
python artemis.py --policy policy.json --run-id staging-2026-001
```

With a local OpenAPI document:
```bash
python artemis.py --policy policy.json --openapi openapi.json --run-id api-staging-001
```

With app-specific tests:
```bash
python artemis.py --policy policy.json --scenarios examples/scenarios.example.json \
  --workflow examples/payment_workflow.example.json --run-id payment-test environment-001
```

Import scanner findings from SARIF (e.g., exported by a compatible SAST/SCA tool):
```bash
python artemis.py --policy policy.json --sarif semgrep.sarif --sarif codeql.sarif --dry-run
```
SARIF-only import can run with no API key and does not contact the target:
```bash
python artemis.py --policy policy.json --sarif results.sarif --sarif-only --run-id source-scan-import
```

## Optional state-changing scenario runs

Default methods are read-only. To enable authored test environment workflows that mutate disposable test data, all of the following must be true:
1. The policy's `allow_state_changing_tests` is `true`.
2. `allowed_methods` explicitly lists the required methods.
3. The scenario has `safe_for_automation: true`, a `disposable_test_data: true` declaration, and a non-empty `cleanup` list for state-changing steps.
4. The environment variable is set:
```bash
export APPSEC_LAB_ACK_STATE_CHANGES='I_ACKNOWLEDGE_DISPOSABLE_LAB_DATA'
```
The AI still only selects the registered scenario ID. It cannot compose HTTP requests. Cleanup steps are run in `finally`; cleanup failures are recorded as high-priority findings. Test the cleanup behavior against a local fixture first.

## Important operational notes
- ARTEMIS makes no network request when `--dry-run` is used.
- Private/internal targets are blocked unless `allow_private_networks` is deliberately enabled for the known test environment.
- Redirects are not followed; each redirect target must be independently in scope.
- Model output is untrusted and is parsed against a strict schema and registered catalog.
- Evidence files may contain request/response bodies, test environment tokens, cookies, or personal data. Keep `runs/` private and out of Git.
- The scope gate is a safety control, not proof of authorization.
- Do not point the tool at public production systems unless the exact target and methods are formally in scope.

## License
ARTEMIS is a new implementation, not a fork or source-code copy of either reference project. See `LICENSE`.


## Personal-use operating principle

ARTEMIS aims to reduce repetitive triage work and raise high-quality, evidence-backed candidates for human verification. A scanner response alone is not proof of exploitability. Each finding includes confidence and an evidence reference; validate impact against the application's expected contract.

## Execution profile

The default profile favors low-impact, read-oriented checks. To test state changes, the operator must define the scenario, request shape, test data, expected outcome, and cleanup. The model cannot invent network requests. This makes automation repeatable and reduces false positives or unintended writes.

## ARTEMIS CLI options

See [`docs/architecture/current-state.md`](docs/architecture/current-state.md), [`docs/architecture/target-state.md`](docs/architecture/target-state.md), [`docs/engineering/capability-parity-matrix.md`](docs/engineering/capability-parity-matrix.md), [`docs/engineering/advanced-capability-roadmap.md`](docs/engineering/advanced-capability-roadmap.md), [`docs/security/threat-model.md`](docs/security/threat-model.md), and [`docs/testing/quality-and-benchmark-plan.md`](docs/testing/quality-and-benchmark-plan.md) for the engineering inventory and next milestones. For release-specific runtime setup and honest separation of fake versus real isolation evidence, see [`docs/implementation/runtime-verification.md`](docs/implementation/runtime-verification.md); dependency provenance and open license decisions are recorded in [`docs/implementation/license-review-2026-10-24.md`](docs/implementation/license-review-2026-10-24.md) and [`docs/implementation/dependency-license-inventory.json`](docs/implementation/dependency-license-inventory.json).

- `--dry-run`: validate target paths and policy without network requests.
- `--validate-catalog`: verify runnable test IDs and framework mappings.
- `--validate-state [path]`: validate graph references in a saved blackboard without sending network requests.
- `--sarif-only --sarif file.sarif`: import findings without target traffic.
- `--hint "..."`: steer the planner toward an assessment priority.
- `--openapi openapi.json`: map endpoints and optionally test concrete in-scope read endpoints.
- `--scenarios examples/scenarios.example.json`: execute enabled, declared scenarios.
- `--workflow examples/payment_workflow.example.json`: register workflow invariants in the findings report.

## Execution safety and repeatability

Exact host allowlists, method policy, TLS verification, per-run budgets, response caps, and stop-on-repeated-server-errors are execution controls—not a substitute for operator judgement. Do not expose credentials in model prompts or commit raw evidence to source control.

## v2.2.9 cancellation boundary

Durable job cancellation now invokes registered execution-supervisor callbacks for every persisted running execution and commits cancellation only after each callback confirms termination. A missing or failing supervisor leaves the job/task state unchanged and records a cancellation-denied event. Container names are derived deterministically from execution IDs, allowing a restarted supervisor to inspect, stop and remove a leftover container. This is a runtime-store cancellation contract, not a complete dispatcher: no production path currently launches authorized `http_request` actions, and the gateway remains fail-closed until real container and egress enforcement are deployed and verified.

## v2.2.8 execution boundary

The legacy deterministic HTTP client now passes every request through a policy-digest/scope authorization gate and only permits GET/HEAD/OPTIONS in that path. The pinned-container supervisor verifies the local image digest before launch and requests network-disabled execution, a read-only filesystem, non-root identity, capability drop, resource ceilings and timeout/cancellation handling. A scoped CONNECT broker and dry-run-first nftables rule generator are available, but they are not wired to worker networking and no host firewall changes were applied. Network-required queue dispatch remains blocked until real runtime validation, enforced egress and cancellation integration are complete. See `docs/operations/scoped-egress.md`.

## Hosted model budget controls

Hosted model use requires an explicit provider/model-bound `llm_budget` policy. See [`docs/operations/model-budget.md`](docs/operations/model-budget.md).

## Traffic journal and local dashboard

Each completed HTTP exchange is written as redacted evidence plus a `traffic.jsonl` index record. Findings automatically inherit exact traffic IDs when their evidence IDs resolve. Verify the journal and its evidence-manifest integrity with `python artemis.py --verify-traffic runs/<run-id>`. This is client-level capture, not a transparent proxy, and binary/raw secret-bearing payloads are not retained.

The loopback-only operator API serves a same-origin dashboard at `/` with persisted health, jobs/tasks, assessment findings/assets/claims/events/traffic and approvals. Job cancellation and approval decision/revocation controls are enforced by server-side roles; remote TLS/identity-provider integration is not included.

## Finding verification and benchmark regression checks

Independent deterministic verification now covers security headers, cookie attributes, cache policy, content type, disclosure, CORS, server errors, advertised HTTP methods and anonymous access boundaries. Persisted verification decisions update matching blackboard claims only when the original and retest evidence both exist; restart reconciliation replays durable decisions. Other finding classes remain pending verification.

`appsec_agent.benchmark.compare_to_baseline()` compares precision/recall/F1 regression deltas and runtime/request/cost increases against an explicitly identified baseline and explicit thresholds. No real scanner baseline is bundled or claimed; that baseline and CI wiring remain open.

## Benchmark regression gate

Use `python artemis.py --benchmark-compare benchmark-comparison.json` to compare a current metrics report against a named baseline with explicit quality/resource thresholds. The command returns exit code 2 on a regression. See [`docs/operations/benchmark-regressions.md`](docs/operations/benchmark-regressions.md). A real scanner-generated baseline and CI workflow still need to be supplied.
