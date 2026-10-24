"""Restart reconciliation for blackboard test outcomes and persisted evidence."""
from __future__ import annotations
import json
import pathlib



def reconcile_verification_claims(run_dir, board) -> list[dict]:
    """Replay persisted verifier decisions into matching blackboard claims.

    The verification history is the durable source of truth. This makes a crash
    after appending a verification decision but before updating the blackboard
    recoverable on the next assessment reconciliation.
    """
    root = pathlib.Path(run_dir)
    evidence_ids = set()
    evidence_path = root / "evidence.jsonl"
    if evidence_path.exists():
        for line in evidence_path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                if item.get("evidence_id"):
                    evidence_ids.add(item["evidence_id"])
            except json.JSONDecodeError:
                continue
    history_path = root / "verification_history.jsonl"
    if not history_path.exists():
        return []
    latest = {}
    for line in history_path.read_text(encoding="utf-8").splitlines():
        try:
            decision = json.loads(line)
            if isinstance(decision, dict) and decision.get("finding_id"):
                latest[decision["finding_id"]] = decision
        except json.JSONDecodeError:
            continue
    updates = []
    for claim in board.data.get("claims", []):
        provenance = claim.get("provenance") if isinstance(claim.get("provenance"), dict) else {}
        finding_id = provenance.get("finding_id")
        decision = latest.get(finding_id)
        if not decision:
            continue
        retest_id = decision.get("evidence_id")
        original_id = decision.get("original_evidence_id")
        if not retest_id or not original_id or retest_id not in evidence_ids or original_id not in evidence_ids:
            continue
        outcome = decision.get("outcome")
        target_status = "verified" if outcome == "corroborated" else "inconclusive"
        evidence_refs = [original_id, retest_id]
        if claim.get("status") == target_status and set(evidence_refs).issubset(set(claim.get("evidence_ids", []))):
            continue
        updated = board.update_claim_status(claim["id"], target_status, reviewer=decision.get("verifier_id", "deterministic-verifier"),
                                            rationale=decision.get("checker_rationale", "Persisted deterministic verification decision"),
                                            evidence_ids=evidence_refs)
        updates.append({"claim_id": claim["id"], "finding_id": finding_id, "status": updated["status"]})
    return updates

def reconcile_assessment(run_dir, board) -> dict:
    root = pathlib.Path(run_dir)
    evidence_ids = set()
    path = root / "evidence.jsonl"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                if item.get("evidence_id"): evidence_ids.add(item["evidence_id"])
            except json.JSONDecodeError:
                continue
    claim_updates = reconcile_verification_claims(root, board)
    reopened = []
    facts_by_test = {}
    for fact in board.data.get("facts", []):
        facts_by_test.setdefault(fact.get("test_id"), []).append(fact)
    for test_id, status in list(board.data.get("test_statuses", {}).items()):
        if status.get("status") != "executed":
            continue
        facts = facts_by_test.get(test_id, [])
        has_durable_support = any(f.get("evidence_id") in evidence_ids for f in facts if f.get("evidence_id"))
        result = status.get("result") or {}
        result_evidence = result.get("evidence_id") if isinstance(result, dict) else None
        has_durable_support = has_durable_support or bool(result_evidence and result_evidence in evidence_ids)
        # Some deterministic offline checks legitimately produce no HTTP evidence;
        # they remain executed only if a persisted fact explicitly documents the result.
        if not facts and not has_durable_support:
            board.set_test_status(test_id, "stale", reason="Restart reconciliation: no persisted fact/evidence supports prior executed status",
                                  result={"prior_result": result, "reconciliation": "missing_durable_outcome"})
            reopened.append(test_id)
    board.save()
    return {"reopened_for_review": sorted(reopened), "evidence_count": len(evidence_ids),
            "checked_tests": len(board.data.get("test_statuses", {})), "claim_updates": claim_updates}
