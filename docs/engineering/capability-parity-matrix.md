# ARTEMIS Capability Parity Matrix

**Status vocabulary:** `implemented`, `partial`, `missing`, `documented_unverified`, `incompatible/not_selected`, `planned`.

The upstream review uses public README/docs, repository directory structures, license files, and selected source files. Capability claims below are based on that evidence and the ARTEMIS archive. This is a working matrix, not a claim that every upstream source file and issue has been exhaustively reviewed.

| Capability | Cairn reference | ARTEX reference | ARTEMIS baseline | Current disposition / acceptance criterion |
|---|---|---|---|---|
| Shared blackboard | Fact/intent/hint graph | Per-task exploration graph | `partial` | Local durable graph exists; schema/provenance/claim lifecycle now expanded. Require migration, integrity tests and lineage checks. |
| OODA loop | Bootstrap/reason/explore | Planner/worker loop | `partial` | Bounded observe/plan/execute loop exists. Require persisted task lifecycle and recovery tests. |
| Dynamic intent generation | Runtime reasoning from graph | Planner is sole intent generator | `partial` | Model chooses registered tests; no general state-space action model. Require objective-driven candidate generation and budgeted search. |
| Intent dependencies | Graph-derived exploration | Shared planner todo/dependencies | `partial` | Todo dependencies exist; status validation and missing-dependency rejection added. Need resumable dependency scheduler and cycle-proof tests. |
| Concurrent workers | Dispatcher schedules worker tasks | Multiple worker goroutines per task | `missing` | No worker pool/dispatcher in ARTEMIS. Add only after durable lease/state backend exists. |
| Isolated worker runtime | Per-project container or local mode | Worker execution environment | `missing` | CLI runs checks in process. Require least-privilege worker isolation and cleanup tests before arbitrary tools. |
| Multiple model backends | Claude Code, Codex, Pi drivers | Provider abstraction and configured agents | `partial` | OpenAI/Anthropic/offline planner adapters; no worker SDK/runtime backends. |
| Durable task state | Server-managed project/fact/intent state | PostgreSQL tasks/exploration/activity | `partial` | JSON blackboard remains local; a separate transactional SQLite runtime queue now persists jobs/tasks/dependencies/events with leases, retries, cancellation and expiry recovery. Still single-host; reconcile runtime tasks with blackboard evidence and use PostgreSQL for multi-host dispatch. |
| Claim/lease/heartbeat | Intent and reason leases/timeouts | Worker/task lifecycle and cancellation | `partial` | Local SQLite task claims, exclusive leases, heartbeat, retries and expiry recovery are implemented/tested. No background supervisor, OS process management or multi-host dispatch. |
| Asset graph | Not a core first-class global graph in the inspected Cairn docs | Global normalized asset graph linked to per-task exploration graph | `partial` | OpenAPI inventory exists; basic in-run target asset node added. Cross-run asset graph, relationships and history remain planned. |
| Exploration graph anchors | Fact-intent lineage | Exploration nodes anchored to assets | `partial` | Facts/intents/claims/assets and edges exist locally. Need complete anchor and graph query model. |
| Trace retrieval | Dispatcher/worker logs and protocol history | Search/list/get prior worker traces | `partial` | Structured per-run trace records and search API added; retrieval is not yet a first-class planner tool across workers. |
| Human hints | Shared graph hints | Main-agent/HITL controls | `partial` | CLI hints are persisted. Approval queue, review UI and controlled scope amendment missing. |
| Exact-action approval | Not equivalent in inspected core design | Tool intercept/approval gate | `missing` | No approval records/gateway. Must bind approval to action parameters, target, policy version and expiry. |
| Traffic recording proxy | Not a core capability in inspected Cairn docs | Recording MITM proxy and traffic-to-finding binding | `partial` | HTTP evidence captured directly by ARTEMIS; no proxy-based recording or traffic UI. |
| Evidence capture | Facts and execution results | Traffic, tool transcript, finding evidence | `partial` | JSONL evidence, original response hash, common secret redaction, binary body omission, and safer evidence file writes exist. Tamper-evident chain, retention controls, and exhaustive redaction remain missing. |
| Finding verification | Facts can prove goal state | Finding lifecycle and dedicated retest workflow | `partial` | Scanner/check findings now become `pending_verification` claims. Independent verifier and retest history are not yet implemented. |
| Contradiction handling | Graph facts and intents | Planner sees graph and worker outcomes | `partial` | Claim records can reference contradictions; automated conflict detection/resolution is missing. |
| Negative evidence | Facts can record outcomes | Worker results/traces can inform planner | `partial` | Basic observations persist; normalized negative result states and coverage semantics need expansion. |
| OpenAPI inventory | Not a primary documented Cairn primitive | Asset/API tools available through agent toolset | `partial` | OpenAPI endpoint inventory and optional GET probing exist. Need schema validation and broader contract testing. |
| SAST/SCA execution | External tools can be worker capabilities | Tool/MCP integration ecosystem | `partial` | SARIF import only. Actual scanner adapters and SBOM analysis are missing. |
| MCP/skill integrations | Worker drivers, not a generic MCP core in inspected docs | MCP and versioned skills | `missing` | No generic adapter registry. Require schema, permissions, timeout, output cap and audit contract. |
| Operator UI | Cairn server UI for projects/facts/intents/hints | Dashboard, assets, traces, approvals, traffic, findings and settings | `missing` | No frontend/API. Build after backend lifecycle and auth model stabilize. |
| Reporting | Graph and task status | Findings, retests and reports | `partial` | Local Markdown/JSON reports. Need confidence, uncertainty, provenance, history and coverage gaps. |
| Budget and cost controls | Dispatcher/runtime configuration | LLM usage/token/cost records | `partial` | HTTP request budget and planner iteration limit exist; provider cost accounting and global worker quotas missing. |
| Cancellation/kill switch | Project stop and worker cancellation in dispatcher | Task cancellation and kill-work control | `partial` | Runtime CLI can cancel jobs and invalidate task leases; actual child/container termination is not implemented. |
| Evaluation suite | Mock end-to-end and runtime/scheduler tests | Broad Go unit/integration tests | `partial` | 51 tests and 7 subtests pass in the current local suite. Need labeled corpus, precision/recall, cost, recovery and ablation metrics. |
| Licensing | AGPL-3.0; commercial terms mentioned in upstream README | AGPL-3.0 plus repository README states additional usage restrictions | `documented_unverified` | ARTEMIS currently has its own MIT license and no upstream source copied. Obtain legal review before copying code or claiming compatibility with upstream additional terms. |

## Source references

- Cairn repository and README: https://github.com/oritera/Cairn
- Cairn dispatcher design: https://github.com/oritera/Cairn/blob/main/docs/specs/dispatcher-design.md
- Cairn server protocol: https://github.com/oritera/Cairn/blob/main/docs/specs/server-protocol.md
- ARTEX repository and README: https://github.com/trhhubsd/ARTEX
- ARTEX planner: https://github.com/trhhubsd/ARTEX/blob/main/agent/planner.go
- ARTEX worker: https://github.com/trhhubsd/ARTEX/blob/main/agent/worker.go
- ARTEX finding workflow: https://github.com/trhhubsd/ARTEX/blob/main/agent/finding_workflow.go
- ARTEX capture: https://github.com/trhhubsd/ARTEX/blob/main/agent/capture.go

## License note

Cairn and ARTEX publish AGPL-3.0 license files. ARTEX's README also states additional usage restrictions. This matrix is not legal advice. ARTEMIS must not copy upstream source without reviewing license compatibility and all applicable terms. The present implementation uses independent code and architectural observations only.
