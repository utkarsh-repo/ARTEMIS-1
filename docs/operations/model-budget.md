# Hosted model budget controls

ARTEMIS requires an explicit `llm_budget` policy object before using a hosted model provider. The budget is initialized before the assessment engine sends any target requests. Offline deterministic planning does not require this object.

Example (replace provider/model and rates with the exact provider account pricing in use):

```json
{
  "llm_budget": {
    "provider": "openai",
    "model": "gpt-6-luna",
    "max_requests": 12,
    "max_input_tokens": 20000,
    "max_output_tokens": 900,
    "max_total_tokens": 25000,
    "max_cost_usd": 0.10,
    "input_cost_per_1k_usd": 0.001,
    "output_cost_per_1k_usd": 0.004
  }
}
```

The rates above are illustrative only, not a claim about current provider pricing. The configured provider and model must exactly match `AI_PROVIDER` and the effective `OPENAI_MODEL` or `ANTHROPIC_MODEL`. Update rates whenever the selected model's pricing changes.

## Enforcement behavior

- Before each hosted API call, ARTEMIS persists a reservation for one request, conservative input-token allowance, configured output-token cap and worst-case cost at the configured rates.
- Input admission uses UTF-8 byte length as a conservative token upper-bound estimate. The provider request itself is capped by `max_output_tokens`.
- When the provider returns usage, the ledger settles against reported input/output token counts. If usage exceeds the reservation or configured budget, ARTEMIS records the overrun and stops subsequent hosted calls.
- If a call fails before usage is available, the reservation remains charged conservatively. It is not silently refunded.
- `model_budget.json` is assessment-local, atomically replaced and created with restrictive permissions. Its limits must match on restart; changing limits mid-run is rejected.
- Budget exhaustion stops planner selection rather than falling back to another hosted call. The deterministic offline fallback is still used for ordinary provider errors that are not budget exhaustion; it does not issue an API call.

## Limitations

The ledger is a local single-process assessment ledger, not a distributed multi-worker accounting service. Protect the assessment directory from untrusted writers. Cost control depends on the operator configuring accurate model-specific rates; ARTEMIS cannot infer provider account pricing. A provider-side usage report is authoritative when available. This is an application-level cap, not a provider billing guarantee if configured pricing is wrong.
