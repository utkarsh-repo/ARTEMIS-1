# ARTEMIS Threat Model

## Scope and assumptions

ARTEMIS is a local Python CLI that sends bounded HTTP requests to explicitly configured assessment targets, optionally uses a remote LLM planner, imports scanner results, and stores evidence locally. The current archive has no authenticated web service or multi-user UI. Future server/UI/worker features require a new threat-model review.

## Assets to protect

- Scope policy, approval state and operator intent.
- API tokens, cookies, provider keys and other credentials.
- Raw HTTP requests/responses and application data captured as evidence.
- Findings, claims, graph provenance and run history.
- Local filesystem state and integrity of the assessment record.
- Target availability and integrity, including disposable test data.
- LLM budget and assessment runtime resources.

## Trust boundaries

1. Operator-authored policy versus runtime inputs.
2. ARTEMIS deterministic authorization gate versus planner output.
3. Target-controlled response bodies, headers, HTML, JSON and error messages.
4. External LLM provider and its API endpoint.
5. Imported SARIF/OpenAPI/scenario/workflow documents versus trusted configuration.
6. Local evidence files versus reports or model-safe observations.
7. Current assessment state versus future cross-assessment memory.

## Threats and controls

| Threat | Current or planned control | Remaining gap |
|---|---|---|
| Prompt injection in target content | Planner instructions treat observations as untrusted; model can select only registered test IDs | Add explicit untrusted-content envelopes and adversarial fixtures; ensure all tool outputs are similarly treated |
| Scope expansion by model | Registered test catalog and deterministic URL/method policy gate | Test every execution path and future adapter; policy must not rely on prompt compliance |
| Path-prefix confusion | Path prefix matching now requires a path boundary; nested encoded traversal is rejected | Add property/fuzz tests for encoded separators, dot segments, Unicode and server normalization differences |
| DNS rebinding / TOCTOU | DNS checks in policy | Socket destination is not pinned to validated addresses; hardening required |
| Redirect to out-of-scope host | Redirects disabled in HTTP client | If redirect support is added, revalidate each hop and cap hop count |
| Credential leakage to LLM | Planner receives `safe_observation`; credential values are local environment variables | Expand redaction corpus; prove secrets do not enter trace, error, report or model context |
| Evidence leakage at rest | Run directory and evidence files use restrictive permissions | Add retention policy, explicit redaction-at-rest options, secure deletion policy and deployment guidance |
| State corruption | Blackboard now fails closed on malformed JSON and uses atomic writes | Multi-process writes are not transactionally coordinated; no checksummed append-only audit chain |
| False-positive inflation | Finding candidates enter `pending_verification`; reports do not imply full standard coverage | Independent verifier, calibrated confidence and labeled corpus remain missing |
| Duplicate or conflicting tasks | Intent deduplication and completed-test tracking | No leases/transactional concurrency; restart and parallel-worker semantics not yet complete |
| Run identifier/path abuse | CLI sanitizes run IDs | Add tests for path traversal, collisions and safe run-directory creation across platforms |
| Malicious imported files | JSON/SARIF/OpenAPI parsing with bounded local workflows | Add file size/depth limits and malformed-input fuzzing before untrusted multi-user ingestion |
| Cost exhaustion | Request and iteration budgets; bounded planner intents | Add provider monetary/token limits, retry ceilings and global budgets |
| Unsafe state-changing test | Policy opt-in, explicit environment acknowledgement and authored cleanup | Cleanup failure recovery and approval-bound mutation are not comprehensive |
| Worker escape/host compromise | No arbitrary worker shell in current ARTEMIS runtime | Any future external tool execution must be sandboxed, least-privilege, time/resource bounded, and auditable |
| Cross-assessment data leakage | Current state is per run | Future global memory must enforce scope/tenant boundaries and avoid sensitive-data reuse |

## Security invariants

- The LLM cannot authorize itself or broaden scope.
- Every network request passes deterministic policy checks.
- Unknown or malformed authorization state blocks execution.
- A candidate finding is not verified because a model says so.
- A negative test result is distinct from an execution failure or untested area.
- Raw evidence is sensitive by default.
- Future approvals must bind to exact parameters, target, policy version and expiry.
- Future worker execution must be isolated and cancellable.

## Residual risk statement

This threat model is a design artifact, not a certification. ARTEMIS remains a prototype until destination enforcement, evidence handling, state recovery, independent verification and adversarial tests are implemented and reviewed.
