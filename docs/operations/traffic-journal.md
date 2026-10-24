# HTTP traffic journal

ARTEMIS writes a redacted evidence record and a corresponding `traffic.jsonl` index row for each completed HTTP exchange. Transport failures also receive unique evidence and traffic IDs. `traffic_id` references are attached to findings when the finding's `evidence_id` resolves to a persisted exchange.

Verify a run with:

```bash
python artemis.py --verify-traffic runs/run-001
```

Exit status is zero only when traffic IDs are unique, every traffic record resolves to an evidence record, findings do not contain unknown traffic IDs, response hashes match, and the chained evidence manifest verifies. A nonzero exit means the run should not be treated as integrity-verified.

The journal stores redacted request/response material in `evidence.jsonl` and metadata/body hashes in `traffic.jsonl`. It does not retain raw credentials, raw secret-bearing payloads, or binary response bodies. It is client-level request capture, not a transparent proxy; requests performed outside `LabHTTPClient` are not captured by this journal. The manifest is local tamper evidence, not an externally anchored signature.
