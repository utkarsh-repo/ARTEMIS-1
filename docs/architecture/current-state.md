# ARTEMIS Current-State Architecture

**Audit basis:** uploaded `ARTEMIS-appsec.zip`, inspected 2026-10-24. Baseline test command: `python -m pytest -q` (12 passed before changes).

## Runtime inventory

| Area | Verified in repository | Current limitation |
|---|---|---|
| Entry point | `artemis.py` delegates to `agent.py`; `--version`, policy, dry-run, catalog validation and SARIF import options exist | CLI only; no service/API/UI |
| Execution | `appsec_agent/engine.py` executes registered tests and a bounded planner loop | Sequential local loop, no durable distributed scheduler or worker process isolation |
| Planner | `planner.py` uses offline priority ranking or OpenAI/Anthropic structured JSON planning | Candidate selection only; no explicit state-space search algorithm or calibrated information gain |
| Shared state | `blackboard.py` persists facts, intents, hints, graph edges, and todos to JSON | No transactional database, no multi-process concurrency protocol, previously no claim lifecycle or graph consistency audit |
| HTTP policy | `policy.py` gates host, method, path, HTTPS, DNS/private IP and state-changing operations | URL checks do not by themselves pin the socket's resolved IP; proxy/DNS rebinding defenses require further work |
| HTTP execution | `http_client.py` applies request budgets, pacing, TLS verification, response caps, and disables redirects | Local requests/session model; no worker isolation or global distributed rate limit |
| Evidence | `evidence.py` records request/response details, hashes, events and deduplicated findings | Full evidence intentionally contains sensitive data; retention and tamper-evident chaining are not implemented |
| Assessment modules | `checks.py`, `openapi_inventory.py`, `scenarios.py` | Coverage depends on configured paths, registered checks, test accounts and expected application contracts |
| External results | `sarif.py` imports SARIF findings | Does not execute SAST/SCA scanners |
| Reporting | `report.py` writes local Markdown and JSON coverage/report artifacts | No dashboard, approval UI, asset coverage graph visualization or notification system |
| Persistence | Per-run JSON/JSONL files | No database migrations, concurrent worker leases, resumable task ownership, or cross-run asset database |
| Tests | `tests/test_core.py`, `tests/test_local_http.py` | Small unit/local HTTP suite; no broad benchmark corpus, fuzzing, provider contract suite, or end-to-end security lab matrix |

## Existing execution sequence

1. Load policy, catalog, optional scenarios/OpenAPI/SARIF inputs.
2. Create local evidence store and per-run blackboard.
3. Execute configured baseline GETs and deterministic checks.
4. Record observations and select additional registered tests with the planner.
5. Execute registered test code only, write facts/intents/events/findings.
6. Generate coverage, run summary, and Markdown report.

The model is not allowed to generate arbitrary network requests. This is an important invariant and must remain enforced by code outside the model.

## Baseline

- `python -m pytest -q`: **12 passed** before the first implementation slice.
- No build system beyond Python source and `requirements.txt` was present.
- No database, frontend, queue, or worker container configuration was present in the uploaded archive.

## Known high-priority correctness and reliability risks

- Original path-prefix checking used plain `startswith`, allowing a configured `/api` prefix to match `/apix`; this was corrected to enforce path boundaries and regression-tested.
- Original blackboard loading silently ignored invalid JSON, risking later overwrite of corrupted state; it now fails closed and preserves the file for inspection.
- Original state persistence used a temporary file without explicit fsync/mode control; it now writes atomically with restrictive file permissions and fsync where supported.
- Findings had no first-class lifecycle distinct from scanner/check output; a claim lifecycle has been added, and imported findings begin as `pending_verification`.
- DNS validation and actual socket connection are separate operations. IP pinning/rebinding protection remains a required hardening item before treating the network boundary as production-grade.
- Existing HTTP evidence may contain credentials, cookies, personal data, or proprietary bodies. Access control, retention, and redaction-at-rest policy need further work.

## Audit scope limitation

This is a source audit of the uploaded ARTEMIS archive plus a source/documentation-level review of public Cairn and ARTEX repositories. It is not a full independent security audit of either upstream project, and no upstream code was copied into ARTEMIS.
