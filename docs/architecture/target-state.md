# ARTEMIS Target-State Architecture

## Design principles

1. **Policy outside the model:** only deterministic policy code authorizes execution.
2. **Evidence before conclusions:** every material claim links to facts/evidence and has an explicit verification state.
3. **Separate global assets from assessment reasoning:** the asset graph persists normalized in-scope asset identity; each assessment has an isolated exploration graph.
4. **Durable workflow:** task transitions, ownership, retries, approvals and cancellation are persisted and auditable.
5. **Structured collaboration:** planners and workers exchange typed records through shared state and trace retrieval, not uncontrolled agent-to-agent conversations.
6. **Measurable autonomy:** search, ranking, verification and stopping policies must be evaluated against deterministic fixtures and labeled ground truth.
7. **Fail closed:** malformed policy, corrupted state, stale approval, missing scope, or uncertain authorization blocks action.

## Target logical components

- **CLI/API control plane:** create assessments, validate policy, pause/resume/cancel runs, review approvals, and export reports.
- **Policy/authorization gate:** exact target and path scope, method and test-category allowlists, destination resolution controls, approval binding, budgets, time limits, and kill switch.
- **Assessment coordinator:** durable lifecycle, idempotent scheduling, task dependencies, lease/recovery semantics, worker limits and cancellation.
- **Planner:** state-aware candidate generation and ranking; sole owner of intent creation; deterministic fallback and bounded search.
- **Workers:** execute one assigned authorized intent through typed tool contracts and isolated processes/containers where supported.
- **Knowledge layer:** facts, claims, hypotheses, contradictions, negative observations, hints, todos, trace index, provenance and version history.
- **Asset graph:** normalized asset identities, ownership/scope membership, relationships, source timestamps, historical sightings and assessment anchors.
- **Evidence store:** request/response records, artifact hashes, redaction metadata, retention/deletion policy, and finding evidence links.
- **Verification service:** deterministic or independently corroborated checks; it never promotes a claim solely because an LLM says so.
- **Integration adapters:** OpenAPI, SARIF, SAST/SCA/SBOM, MCP-compatible providers and approved tool integrations, each with schema, permissions, limits and audit records.
- **Reporting/UI:** coverage and uncertainty, graph lineage, approvals, traces, findings lifecycle, retest comparisons, usage and cost.
- **Evaluation harness:** local vulnerable fixtures, known-negative cases, regression corpus, ablations, accuracy/cost/reliability metrics.

## Graph model

### Asset graph

Cross-assessment records are normalized and deduplicated by typed canonical identity. Each asset records source/provenance, first/last-seen timestamps, scope status, ownership context, relationships and historical sightings. An asset is not authorized merely because it appears in the graph.

### Exploration graph

Per-assessment nodes include goals, intents, facts, claims/findings, hints, execution traces and evidence references. Edges include `spawns`, `derived_from`, `yields_fact`, `supports_claim`, `contradicts_claim`, `proves`, `depends_on` and `anchors`. The graph validator checks dangling references and unsupported relationships.

## Delivery sequence

1. State/provenance/claim lifecycle and local graph integrity (started in the current implementation slice).
2. Scope enforcement hardening and evidence redaction/retention.
3. Persistent task lifecycle, resumability, idempotency and cancellation.
4. Asset graph persistence and asset anchors.
5. Trace retrieval, dependency-aware planning and deterministic information-value baseline.
6. Independent verification and retesting.
7. Tool adapters and source/supply-chain scanning.
8. API/UI and approval queue.
9. Evaluation benchmarks, fault injection and measured optimization.

## Persistence strategy

The current local JSON implementation is suitable for a single-process prototype. Before concurrent workers or multi-user service operation, move task/graph records to a transactional store with migrations, uniqueness constraints, compare-and-swap or row-lock based leases, and tested recovery semantics. Do not emulate distributed locking with uncoordinated JSON writes.
