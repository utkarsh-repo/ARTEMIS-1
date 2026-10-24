"""Exact-action, expiring, one-time human approval primitives.

This module records approval decisions and provides an atomic consume operation.
It is not an execution sandbox: callers must consume the approval immediately
before dispatch and independently enforce policy, tool schemas and egress rules.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from typing import Any

from .policy import PolicyError, validate_url
from .runtime_store import InvalidTransition, RuntimeStore, RuntimeStoreError, policy_digest as digest_policy
from .tool_registry import ToolSchemaError, validate_tool_action

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_MAX_ACTION_BYTES = 65536


def _validate_json_value(value: Any, path: str = "parameters") -> None:
    """Reject ambiguous/non-JSON values before canonical hashing."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} object keys must be strings")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path} contains unsupported value type {type(value).__name__}")


def _canonical(value: Any) -> str:
    _validate_json_value(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def action_digest(*, job_id: str, target: str, tool_name: str, parameters: dict[str, Any], policy_digest: str) -> str:
    """Hash the exact action tuple; parameter changes necessarily change the digest."""
    if not isinstance(job_id, str) or not job_id.strip() or len(job_id) > 256:
        raise ValueError("job_id must be a non-empty string of at most 256 characters")
    if not isinstance(target, str) or not target.strip() or len(target) > 4096 or any(ord(c) < 32 for c in target):
        raise ValueError("target must be a non-empty string without control characters")
    if not isinstance(tool_name, str) or not _NAME.fullmatch(tool_name):
        raise ValueError("tool_name must be a valid tool identifier")
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be a JSON object")
    if not isinstance(policy_digest, str) or not policy_digest.strip() or len(policy_digest) > 256:
        raise ValueError("policy_digest must be a non-empty string of at most 256 characters")
    payload = {"job_id": job_id, "target": target, "tool_name": tool_name,
               "parameters": parameters, "policy_digest": policy_digest}
    encoded = _canonical(payload)
    if len(encoded.encode("utf-8")) > _MAX_ACTION_BYTES:
        raise ValueError(f"action parameters exceed {_MAX_ACTION_BYTES} bytes")
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ApprovalGateway:
    """Persist and atomically consume approvals through a RuntimeStore."""

    def __init__(self, store: RuntimeStore, policy: dict[str, Any] | None = None):
        self.store = store
        self.policy = policy

    def _validate_policy_scope(self, *, target: str, parameters: dict[str, Any], expected_digest: str) -> None:
        if self.policy is None:
            raise RuntimeStoreError("a validated policy snapshot is required for approval request/consumption")
        if digest_policy(self.policy) != expected_digest:
            raise RuntimeStoreError("loaded policy snapshot does not match the action policy digest")
        method = parameters.get("method", "GET")
        if not isinstance(method, str):
            raise ValueError("action parameter 'method' must be a string when provided")
        try:
            validate_url(self.policy, target, method, resolve_dns=False)
        except PolicyError as exc:
            raise RuntimeStoreError(f"action target is outside deterministic policy scope: {exc}") from exc

    def request(self, *, job_id: str, target: str, tool_name: str, parameters: dict[str, Any],
                policy_digest: str, requested_by: str, ttl_seconds: int = 900) -> dict[str, Any]:
        if not isinstance(requested_by, str) or not _NAME.fullmatch(requested_by):
            raise ValueError("requested_by must be a valid operator identifier")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 10 <= ttl_seconds <= 86400:
            raise ValueError("ttl_seconds must be an integer between 10 and 86400")
        try:
            parameters = validate_tool_action(tool_name, parameters)
        except ToolSchemaError as exc:
            raise RuntimeStoreError(str(exc)) from exc
        self._validate_policy_scope(target=target, parameters=parameters, expected_digest=policy_digest)
        digest = action_digest(job_id=job_id, target=target, tool_name=tool_name,
                               parameters=parameters, policy_digest=policy_digest)
        now = time.time()
        approval_id = "approval-" + uuid.uuid4().hex
        with self.store._transaction() as conn:
            job = conn.execute("SELECT status,policy_digest FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise KeyError(f"unknown job: {job_id}")
            if job["status"] in {"complete", "failed", "cancelled"}:
                raise InvalidTransition("cannot request approval for a terminal job")
            if job["policy_digest"] != policy_digest:
                raise RuntimeStoreError("approval policy digest does not match assessment job")
            # Persist only parameter names, never raw values which may contain credentials.
            keys = sorted(str(k)[:200] for k in parameters.keys())
            conn.execute("""INSERT INTO approvals
                (id,job_id,action_digest,target,tool_name,parameter_keys,policy_digest,status,requested_by,created_at,expires_at)
                VALUES(?,?,?,?,?,?,?,'pending',?,?,?)""",
                (approval_id, job_id, digest, target, tool_name, _canonical(keys), policy_digest,
                 requested_by, now, now + ttl_seconds))
            self.store._event(conn, "approval_requested", job_id=job_id,
                              payload={"approval_id": approval_id, "action_digest": digest,
                                       "target": target, "tool_name": tool_name, "expires_at": now + ttl_seconds})
            return self.get(approval_id, connection=conn)

    def decide(self, approval_id: str, *, approver_id: str, approve: bool, reason: str = "") -> dict[str, Any]:
        if not isinstance(approver_id, str) or not _NAME.fullmatch(approver_id):
            raise ValueError("approver_id must be a valid operator identifier")
        if not isinstance(approve, bool):
            raise ValueError("approve must be a boolean")
        if not isinstance(reason, str) or len(reason) > 2000 or any(ord(c) < 32 and c not in "\n\t" for c in reason):
            raise ValueError("reason must be at most 2000 characters without control characters")
        now = time.time()
        with self.store._transaction() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not row:
                raise KeyError(f"unknown approval: {approval_id}")
            if row["status"] != "pending":
                raise InvalidTransition(f"cannot decide approval from {row['status']}")
            if row["expires_at"] <= now:
                conn.execute("UPDATE approvals SET status='expired' WHERE id=?", (approval_id,))
                self.store._event(conn, "approval_expired", job_id=row["job_id"], payload={"approval_id": approval_id})
                return self.get(approval_id, connection=conn)
            if approver_id == row["requested_by"]:
                raise InvalidTransition("requester cannot approve their own action")
            status = "approved" if approve else "rejected"
            conn.execute("UPDATE approvals SET status=?,decided_at=?,decided_by=?,decision_reason=? WHERE id=? AND status='pending'",
                         (status, now, approver_id, reason, approval_id))
            self.store._event(conn, "approval_" + status, job_id=row["job_id"],
                              payload={"approval_id": approval_id, "approver_id": approver_id, "reason": reason})
            return self.get(approval_id, connection=conn)

    def consume(self, approval_id: str, *, job_id: str, target: str, tool_name: str,
                parameters: dict[str, Any], policy_digest: str) -> dict[str, Any]:
        """Consume exactly once; mismatches and stale policy fail closed."""
        try:
            parameters = validate_tool_action(tool_name, parameters)
        except ToolSchemaError as exc:
            raise RuntimeStoreError(str(exc)) from exc
        self._validate_policy_scope(target=target, parameters=parameters, expected_digest=policy_digest)
        digest = action_digest(job_id=job_id, target=target, tool_name=tool_name,
                               parameters=parameters, policy_digest=policy_digest)
        now = time.time()
        with self.store._transaction() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not row:
                raise KeyError(f"unknown approval: {approval_id}")
            if row["revoked_at"] is not None:
                raise InvalidTransition("approval has been revoked")
            if row["status"] != "approved":
                raise InvalidTransition(f"approval is not consumable from status {row['status']}")
            if row["expires_at"] <= now:
                conn.execute("UPDATE approvals SET status='expired' WHERE id=? AND status='approved'", (approval_id,))
                self.store._event(conn, "approval_expired", job_id=row["job_id"], payload={"approval_id": approval_id})
                return self.get(approval_id, connection=conn)
            job = conn.execute("SELECT status,policy_digest FROM jobs WHERE id=?", (row["job_id"],)).fetchone()
            if not job or job["status"] == "cancelled":
                raise InvalidTransition("assessment is missing or cancelled")
            if job["policy_digest"] != policy_digest or row["policy_digest"] != policy_digest:
                raise RuntimeStoreError("current policy digest does not match approval")
            if row["job_id"] != job_id or row["action_digest"] != digest:
                raise RuntimeStoreError("action does not exactly match approved target, tool, parameters and policy")
            updated = conn.execute("UPDATE approvals SET status='consumed',consumed_at=? WHERE id=? AND status='approved'",
                                   (now, approval_id))
            if updated.rowcount != 1:
                raise InvalidTransition("approval was concurrently consumed")
            self.store._event(conn, "approval_consumed", job_id=job_id,
                              payload={"approval_id": approval_id, "action_digest": digest})
            return self.get(approval_id, connection=conn)

    def revoke(self, approval_id: str, *, revoked_by: str, reason: str = "") -> dict[str, Any]:
        """Revoke a pending, approved or consumed action; execution rechecks this flag."""
        if not isinstance(revoked_by, str) or not _NAME.fullmatch(revoked_by):
            raise ValueError("revoked_by must be a valid operator identifier")
        if not isinstance(reason, str) or len(reason) > 2000:
            raise ValueError("reason must be at most 2000 characters")
        now = time.time()
        with self.store._transaction() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not row:
                raise KeyError(f"unknown approval: {approval_id}")
            if row["status"] not in {"pending", "approved", "consumed"}:
                raise InvalidTransition(f"cannot revoke approval from status {row['status']}")
            if row["revoked_at"] is not None:
                raise InvalidTransition("approval is already revoked")
            status = "rejected" if row["status"] == "pending" else row["status"]
            conn.execute("UPDATE approvals SET status=?,revoked_at=?,revoked_by=?,decision_reason=? WHERE id=?",
                         (status, now, revoked_by, reason, approval_id))
            self.store._event(conn, "approval_revoked", job_id=row["job_id"], payload={
                "approval_id": approval_id, "revoked_by": revoked_by, "reason": reason})
            return self.get(approval_id, connection=conn)

    def get(self, approval_id: str, *, connection=None) -> dict[str, Any] | None:
        if connection is not None:
            row = connection.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            return self._decode(row)
        with self.store._connection() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            return self._decode(row)

    @staticmethod
    def _decode(row) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["parameter_keys"] = json.loads(item["parameter_keys"])
        return item

    def list_for_job(self, job_id: str) -> list[dict[str, Any]]:
        with self.store._connection() as conn:
            rows = conn.execute("SELECT * FROM approvals WHERE job_id=? ORDER BY created_at,id", (job_id,)).fetchall()
            return [self._decode(row) for row in rows]
