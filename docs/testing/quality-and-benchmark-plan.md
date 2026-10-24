# ARTEMIS Quality and Benchmark Plan

## Baseline snapshot

- Initial archive baseline: `python -m pytest -q` → 12 passed.
- Baseline source had no CI configuration or benchmark corpus in the uploaded archive.
- Preserve this baseline when comparing future planner or detection changes; do not compare runs with different target fixtures or policies without recording the difference.

## Test layers

### Unit tests

- Policy: host allowlist, scheme, method, path boundary, traversal/encoding, credentials, IP ranges and port handling.
- Blackboard: schema migration, corrupt-state failure, atomic save, idempotent fact/asset/claim creation, legal status transitions, provenance and graph consistency.
- Planner: strict candidate IDs, malformed model output, fallback behavior, prompt-injection-like observation strings, candidate duplication and budget limits.
- Evidence: secret redaction, hash stability, permissions, size caps, deduplication and sensitive data handling.
- Coverage/reporting: distinguish executed, failed, blocked, deferred, not-run and stale checks.

### Integration tests

- Local HTTP fixture with deterministic headers, cookies, redirects, 4xx/5xx, oversized responses and transport failures.
- End-to-end dry-run proving zero network requests.
- Full offline run against a local fixture, checking all expected artifacts and claim lifecycle statuses.
- Resume/restart fixtures once durable lifecycle is implemented.
- Approval exact-match/expiry/rejection fixtures once approval is implemented.

### Security tests

- Scope bypass attempts through URL normalization, encoded path segments, alternate IP representations, DNS changes and redirects.
- Prompt injection in body/header/OpenAPI/SARIF/scenario descriptions.
- Secret leakage into LLM payloads, logs, traces, reports and filenames.
- State file truncation/corruption and concurrent writers.
- Tool timeout, output cap, cancellation and cleanup failure.
- Malformed JSON, deeply nested inputs and oversized artifacts.

### Property/fuzz tests

Use Hypothesis or equivalent after adding the dependency deliberately. Generate URL/path variants, graph edges, state transitions and malformed imported records. Keep seed cases for every discovered defect.

## Accuracy benchmark

Create a versioned local corpus with known-positive, known-negative and inconclusive cases. Store ground truth separately from the model's view. Include vulnerable and fixed variants of each fixture. Do not test against third-party production systems as part of benchmark automation.

Measure:

- Precision = true positives / all reported positives.
- Recall = true positives / all known positives.
- False-positive rate on known-negative cases.
- Evidence completeness and reproducibility.
- Verification outcome accuracy.
- Duplicate finding rate.
- Coverage status accuracy, including proof that deferred/failed/blocked tests are not counted as executed.
- Time to verified conclusion.
- Requests and tool invocations per verified result.
- LLM tokens and monetary cost per run.
- Repeated-action rate.
- Crash recovery and cancellation success.

For any metric without ground truth, report it as descriptive rather than accuracy. Do not treat an LLM's self-reported confidence as calibrated probability.

## Comparative experiment protocol

1. Pin code revision, test corpus, target fixture, policy, provider/model and prompt version.
2. Run the deterministic baseline and proposed method on the same cases.
3. Repeat stochastic runs where applicable and report variance.
4. Compare accuracy, evidence quality, time, requests, token/cost and safety violations together.
5. Run ablations for trace retrieval, candidate ranking, verification and memory reuse.
6. Reject changes that improve raw finding count but materially worsen precision, safety or reproducibility.

## Release gate

- Unit and integration suites pass or have explicit reproducible blockers.
- No known regression in scope policy or evidence redaction.
- All new configuration fields have defaults, validation and examples.
- Schema migration preserves prior state and has a recovery path.
- Reports accurately label unsupported, blocked and untested categories.
- No claim of superiority over Cairn/ARTEX without controlled comparative results.
