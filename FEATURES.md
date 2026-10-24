
# Feature matrix

## Included in this version
- Persistent fact/intent blackboard with deduplication, event journal and operator hints.
- Iterative planner with OpenAI/Anthropic JSON adapters and deterministic fallback.
- Registered check catalog; model cannot construct requests.
- Scope and request policy enforcement at every outbound HTTP operation.
- HTTP baseline and common config checks.
- OpenAPI inventory and optional constrained checks.
- Scenario runner with explicit assertions and cleanup for stateful steps.
- Business-logic invariant templates.
- SARIF import for external code/dependency scan tools.
- Evidence hashes, finding deduplication, run summary, coverage JSON, Markdown report.
- Unit tests plus a local mock-server integration test.

## Partial or external dependencies
- OWASP/CWE are mapped to test modules, but the matrix reports `scenario_required`, `external_tool_required` or `manual_review_required` where appropriate.
- Comprehensive source-level CWE detection requires external SAST/SCA/fuzzing tools and source artifacts.
- Browser testing, real Burp traffic ingestion, a web UI, distributed worker processes, alerting/log-system connectors and artifact storage backends are not bundled.
- Payment-specific assertions require the actual application workflow contract and test data.


## Follow-up work still needed for full coverage
- Add browser automation for authenticated UI workflows (e.g. Playwright) and state snapshots.
- Add actual Burp Suite traffic ingestion / MCP server and a persisted HTTP exchange browser.
- Add parallel workers or isolated worker processes; current engine is one bounded planning loop.
- Add system-level source scanning and dependency analysis; this release can import SARIF but does not run Semgrep/CodeQL/SCA itself.
- Bind payment/business logic templates to the application's actual OpenAPI paths and test fixtures.
- Add a dedicated baseline TLS/configuration scanner; current checks are HTTP response focused.


## Planner improvements
- Durable fact-intent graph and relationship edges.
- Dependency-aware todo store, operator hints, bounded planning rounds, and registered test IDs.
- Planner outputs validated against the catalog; deterministic fallback on malformed/unavailable model responses.
- Finding de-duplication, stable finding IDs, evidence references, and prioritized Markdown report.
