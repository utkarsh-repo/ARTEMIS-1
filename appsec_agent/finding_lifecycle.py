"""Evidence-backed finding verification and append-only retest history.

This module intentionally does not make network requests. Independent verification
must be supplied by a distinct registered deterministic check and backed by stored
HTTP evidence; otherwise the result remains inconclusive.
"""
from __future__ import annotations

import json
import pathlib
import time
import uuid
from typing import Any

from .evidence import EvidenceStore, redact_text


def _records(path: pathlib.Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict): rows.append(item)
        except json.JSONDecodeError:
            continue
    return rows


def _deterministic_verification(finding: dict[str, Any], evidence: dict[str, Any], verifier_id: str) -> tuple[str, str]:
    """Run a fixed independent evidence check; never accept model-supplied outcomes."""
    headers = {str(k).lower(): str(v) for k, v in evidence.get("response", {}).get("headers", {}).items()}
    details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
    check = finding.get("check")
    if verifier_id == "cookie_flags_recheck" and check == "cookie_flags":
        missing = details.get("missing_attributes", [])
        observations = evidence.get("response", {}).get("cookie_attributes", [])
        if not isinstance(missing, list) or not missing:
            return "inconclusive", "finding lacks a bounded missing-cookie-attribute list"
        if not observations:
            return "inconclusive", "retest evidence does not contain sanitized cookie-attribute observations"
        missing = [str(name).lower() for name in missing if str(name).lower() in {"secure", "httponly", "samesite"}]
        if not missing:
            return "inconclusive", "finding contains no supported cookie attributes"
        if any(any(item.get(name) is False for name in missing) for item in observations):
            return "corroborated", "at least one retested cookie still lacks a reported security attribute"
        return "not_reproduced", "all retested cookies contain the originally missing security attributes"
    if verifier_id == "http_method_surface_recheck" and check == "http_method_surface":
        allow = headers.get("allow", "")
        if not allow:
            return "inconclusive", "retest response lacks an Allow header to evaluate advertised methods"
        methods = {item.strip().upper() for item in allow.split(",")}
        risky = methods.intersection({"TRACE", "CONNECT"})
        return ("corroborated", "risky HTTP methods remain advertised: " + ", ".join(sorted(risky))) if risky else ("not_reproduced", "TRACE and CONNECT are not advertised in the retest Allow header")
    if verifier_id == "anonymous_auth_boundary_recheck" and check == "anonymous_auth_boundary":
        status = evidence.get("response", {}).get("status")
        if not isinstance(status, int):
            return "inconclusive", "retest response status is missing"
        if status not in (401, 403):
            return "corroborated", "configured protected path still does not return 401/403 anonymously"
        return "not_reproduced", "retest response enforces an anonymous authentication boundary"
    if verifier_id == "headers_recheck" and check == "security_headers":
        missing = details.get("missing", [])
        if not isinstance(missing, list) or not missing: return "inconclusive", "finding lacks a bounded missing-header list"
        still_missing = [str(name).lower() for name in missing if str(name).lower() not in headers]
        return ("corroborated", "independent response still lacks: " + ", ".join(still_missing)) if still_missing else ("not_reproduced", "all originally missing headers are present in the retest response")
    if verifier_id == "cache_policy_recheck" and check == "cache_policy":
        path = str(details.get("path", "")).lower()
        cache = headers.get("cache-control", "").lower()
        sensitive = any(word in path for word in ("profile", "account", "payment", "order", "user", "token", "session"))
        if not path or "cache-control" not in headers: return "inconclusive", "retest response lacks path or Cache-Control evidence"
        if sensitive and not any(word in cache for word in ("no-store", "private")):
            return "corroborated", "sensitive path still lacks restrictive Cache-Control"
        return "not_reproduced", "retest response has restrictive cache policy or path is not classified sensitive"
    if verifier_id == "content_type_recheck" and check == "content_type":
        ct = headers.get("content-type", "").lower()
        nosniff = "x-content-type-options" in headers
        if not ct:
            status = evidence.get("response", {}).get("status", 0)
            if isinstance(status, int) and status < 400: return "corroborated", "successful response still lacks Content-Type"
            return "inconclusive", "response does not establish a successful missing-Content-Type case"
        if ("text/html" in ct or "application/xhtml" in ct) and not nosniff:
            return "corroborated", "HTML response still lacks X-Content-Type-Options"
        return "not_reproduced", "content type and nosniff checks no longer reproduce the reported condition"
    if verifier_id == "disclosure_recheck" and check == "technology_disclosure":
        names = {"server", "x-powered-by", "x-aspnet-version"}
        found = sorted(names.intersection(headers))
        return ("corroborated", "disclosure headers remain: " + ", ".join(found)) if found else ("not_reproduced", "known disclosure headers are absent")
    if verifier_id == "cors_recheck" and check == "cors_preflight":
        origin = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        vulnerable = credentials and (origin == "*" or origin == "https://appsec-probe.invalid")
        return ("corroborated", "unsafe CORS origin/credentials combination remains") if vulnerable else ("not_reproduced", "unsafe CORS origin/credentials combination not observed")
    if verifier_id == "error_surface_recheck" and check == "error_surface":
        status = evidence.get("response", {}).get("status", 0)
        if not isinstance(status, int): return "inconclusive", "response status is missing"
        if status >= 500: return "corroborated", "server error status remains on independent response"
        return "not_reproduced", "server error status did not recur"
    if verifier_id == "scenario_status_recheck" and check == "scenario_suite":
        status = evidence.get("response", {}).get("status")
        assertion_type = details.get("assertion_type")
        if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
            return "inconclusive", "retest evidence has no valid HTTP status"
        if assertion_type == "status_equals":
            expected = details.get("expected_status")
            if not isinstance(expected, int) or isinstance(expected, bool) or not 100 <= expected <= 599:
                return "inconclusive", "scenario finding lacks a bounded expected status"
            failed_again = status != expected
        elif assertion_type == "status_not_equals":
            expected = details.get("expected_status")
            if not isinstance(expected, int) or isinstance(expected, bool) or not 100 <= expected <= 599:
                return "inconclusive", "scenario finding lacks a bounded expected status"
            failed_again = status == expected
        elif assertion_type == "status_in":
            expected = details.get("expected_statuses")
            if not isinstance(expected, list) or not expected or len(expected) > 20 or any(not isinstance(v, int) or isinstance(v, bool) or not 100 <= v <= 599 for v in expected):
                return "inconclusive", "scenario finding lacks a bounded expected-status set"
            failed_again = status not in expected
        else:
            return "inconclusive", "scenario assertion type is not independently supported"
        return ("corroborated", "independent retest still violates the recorded status assertion") if failed_again else ("not_reproduced", "independent retest satisfies the recorded status assertion")
    raise ValueError("verifier_id is not registered for this finding type")


def verify_candidate(run_dir, finding_id: str, *, verifier_id: str, evidence_id: str,
                     outcome: str | None = None, rationale: str = "") -> dict[str, Any]:
    """Run a fixed deterministic verifier and append the evidence-backed decision.

    ``outcome`` is retained only as a compatibility assertion; it cannot override
    the deterministic result.
    """
    root = pathlib.Path(run_dir)
    if not verifier_id or not isinstance(verifier_id, str): raise ValueError("verifier_id is required")
    findings = _records(root / "findings.jsonl")
    finding = next((f for f in findings if f.get("finding_id") == finding_id), None)
    if finding is None: raise ValueError("unknown finding_id")
    evidence = _records(root / "evidence.jsonl")
    ev = next((e for e in evidence if e.get("evidence_id") == evidence_id), None)
    if ev is None: raise ValueError("verification evidence_id is not persisted")
    original_evidence_id = finding.get("evidence_id")
    if not original_evidence_id or original_evidence_id == evidence_id or not any(
            e.get("evidence_id") == original_evidence_id for e in evidence):
        raise ValueError("candidate requires its own original persisted evidence before independent verification")
    if verifier_id == str(finding.get("check", "")):
        raise ValueError("verification must use a distinct deterministic checker")
    original_url = finding.get("url")
    retest_url = ev.get("request", {}).get("url")
    if original_url and retest_url and retest_url.split("?", 1)[0] != original_url.split("?", 1)[0]:
        raise ValueError("verification evidence target does not match finding target")
    actual_outcome, check_rationale = _deterministic_verification(finding, ev, verifier_id)
    if outcome is not None and outcome != actual_outcome:
        raise ValueError("caller-supplied outcome conflicts with deterministic verifier result")
    decision = {"verification_id": "vr-" + uuid.uuid4().hex[:12], "finding_id": finding_id,
                "verifier_id": verifier_id, "evidence_id": evidence_id, "outcome": actual_outcome,
                "rationale": redact_text(rationale or check_rationale)[:1000], "checker_rationale": check_rationale[:1000],
                "timestamp": time.time(), "original_check": finding.get("check"),
                "original_evidence_id": original_evidence_id}
    store = EvidenceStore(root)
    store.append("verification_history.jsonl", decision)
    # Replay the durable decision into a matching blackboard claim. If the
    # process crashes between these writes, restart reconciliation replays it.
    claim_updates = []
    board_path = root / "blackboard.json"
    if board_path.exists():
        from .blackboard import Blackboard
        from .reconciliation import reconcile_verification_claims
        board = Blackboard(board_path)
        claim_updates = reconcile_verification_claims(root, board)
        board.save()
    decision["claim_updates"] = claim_updates
    return decision


def record_retest(run_dir, finding_id: str, *, status: str, evidence_ids: list[str],
                  reviewer: str, rationale: str = "") -> dict[str, Any]:
    """Record a remediation retest without modifying the original finding/evidence."""
    if status not in {"open", "remediated", "not_reproduced", "inconclusive"}:
        raise ValueError("unsupported retest status")
    if not reviewer or not isinstance(reviewer, str): raise ValueError("reviewer is required")
    root = pathlib.Path(run_dir)
    findings = _records(root / "findings.jsonl")
    if not any(f.get("finding_id") == finding_id for f in findings): raise ValueError("unknown finding_id")
    available = {e.get("evidence_id") for e in _records(root / "evidence.jsonl")}
    evidence_ids = list(dict.fromkeys(evidence_ids))
    if not evidence_ids or set(evidence_ids) - available:
        raise ValueError("retest requires existing persisted evidence IDs")
    history = _records(root / "retest_history.jsonl")
    prior = [r for r in history if r.get("finding_id") == finding_id]
    record = {"retest_id": "rt-" + uuid.uuid4().hex[:12], "finding_id": finding_id,
              "version": len(prior) + 1, "previous_retest_id": prior[-1]["retest_id"] if prior else None,
              "status": status, "evidence_ids": evidence_ids, "reviewer": redact_text(reviewer)[:200],
              "rationale": redact_text(rationale)[:1000], "timestamp": time.time()}
    EvidenceStore(root).append("retest_history.jsonl", record)
    return record
