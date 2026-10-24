"""Central policy-bound authorization for queued, approval-bound tool actions.

This module records policy-bound authorization and result lifecycle. ARTEMIS
has no independently enforced OS/container worker boundary yet, so the gateway
fails closed instead of allowing an action to enter ``running`` without one.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import os
import pathlib
import stat
import uuid
from typing import Any

from .approval import action_digest
from .evidence import redact_payload
from .policy import PolicyError, validate_url
from .runtime_store import InvalidTransition, LeaseConflict, RuntimeStore, RuntimeStoreError, policy_digest as digest_policy
from .tool_registry import ToolSchemaError, tool_definition, validate_tool_action

_ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")


class AuthorizationDenied(RuntimeStoreError):
    """An action failed one or more independent authorization checks."""


def _canonical_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()




class InlineRequestAuthorizationGateway:
    """Mandatory per-request policy gate for the legacy deterministic HTTP engine.

    Legacy requests are deliberately limited to read-only GET/HEAD/OPTIONS.
    State-changing operations must use the queue's exact-action approval path;
    they are never enabled merely because a scenario or model asks for them.
    The HTTP transport still performs connection-time DNS/IP validation and
    pinning after this authorization check.
    """
    READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(self, policy: dict[str, Any], *, assessment_id: str,
                 audit: Any | None = None):
        if not isinstance(assessment_id, str) or not assessment_id.strip():
            raise ValueError("assessment_id is required for inline request authorization")
        self.policy = policy
        self.policy_digest = digest_policy(policy)
        self.assessment_id = assessment_id
        self.audit = audit or (lambda _event: None)

    _FORBIDDEN_OVERRIDE_HEADERS = frozenset({
        "host", ":authority", "authorization", "proxy-authorization", "proxy-authenticate",
        "proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length",
        "cookie", "set-cookie", "upgrade", "expect", "forwarded", "x-forwarded-host",
        "x-original-url", "x-rewrite-url", "x-http-method", "x-http-method-override",
        "x-method-override",
    })
    _HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

    @classmethod
    def _validate_read_only_overrides(cls, headers: Any, has_body: bool) -> None:
        # Read-only method gating alone is insufficient: Host/authority overrides,
        # method-override headers and GET bodies can change routing or application
        # semantics while the URL itself remains in scope.
        if has_body:
            raise AuthorizationDenied("legacy read-only requests cannot carry a body")
        if headers is None:
            return
        if not isinstance(headers, dict) or len(headers) > 32:
            raise AuthorizationDenied("request headers must be an object with at most 32 entries")
        total = 0
        for name, value in headers.items():
            if (not isinstance(name, str) or not cls._HEADER_NAME.fullmatch(name)
                    or not isinstance(value, str) or len(name) > 128 or len(value) > 4096
                    or any(ch in value for ch in "\r\n\x00")):
                raise AuthorizationDenied("request header shape is invalid")
            if name.lower() in cls._FORBIDDEN_OVERRIDE_HEADERS:
                raise AuthorizationDenied("request contains a routing, authentication or transport override header")
            total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
            if total > 16384:
                raise AuthorizationDenied("request headers exceed the configured size limit")

    def authorize_request(self, url: str, method: str, *, headers: Any = None,
                          has_body: bool = False, auth_profile: str | None = "default") -> dict[str, Any]:
        from urllib.parse import urlparse
        action_id = "inline-" + uuid.uuid4().hex
        normalized_method = method.upper() if isinstance(method, str) else ""
        try:
            if auth_profile not in (None, "default", "anonymous") and not (
                    isinstance(auth_profile, str) and re.fullmatch(r"LAB_(?:TOKEN|COOKIE)_[A-Z0-9_]{1,64}", auth_profile)):
                raise AuthorizationDenied("authentication profile identifier is invalid")
            if digest_policy(self.policy) != self.policy_digest:
                raise AuthorizationDenied("policy snapshot changed")
            if normalized_method not in self.READ_ONLY_METHODS:
                raise AuthorizationDenied("legacy execution only permits read-only HTTP methods")
            self._validate_read_only_overrides(headers, has_body)
            validate_url(self.policy, url, normalized_method, resolve_dns=False)
        except (PolicyError, AuthorizationDenied, TypeError, ValueError) as exc:
            self.audit({"type": "authorization_denied", "assessment_id": self.assessment_id,
                        "action_id": action_id, "policy_digest": self.policy_digest,
                        "method": normalized_method, "reason_code": type(exc).__name__})
            raise AuthorizationDenied("legacy HTTP request denied by execution authorization gateway") from exc
        parsed = urlparse(url)
        header_digest = hashlib.sha256(json.dumps(headers or {}, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8")).hexdigest()
        action_digest = _canonical_digest({"assessment_id": self.assessment_id, "policy_digest": self.policy_digest,
            "url": url, "method": normalized_method, "auth_profile": auth_profile,
            "headers_sha256": header_digest, "has_body": bool(has_body)})
        event = {"type": "authorization_allowed", "assessment_id": self.assessment_id,
                 "action_id": action_id, "action_digest": action_digest, "policy_digest": self.policy_digest,
                 "host": parsed.hostname, "method": normalized_method, "auth_profile": auth_profile,
                 "headers_sha256": header_digest, "tool": "legacy_http_client"}
        # Audit persistence is part of the authorization boundary. If it fails,
        # no request is allowed to proceed.
        self.audit(event)
        return {"assessment_id": self.assessment_id, "action_id": action_id,
                "action_digest": action_digest, "policy_digest": self.policy_digest, "host": parsed.hostname,
                "method": normalized_method, "auth_profile": auth_profile,
                "headers_sha256": header_digest, "state": "authorized"}


class AuthorizationGateway:
    """Authorize a claimed queue task against current trusted state.

    The task input is treated as untrusted planner data. Policy, queue lease,
    approval ledger, registered schema and tool version are re-read/recomputed
    immediately before an authorization record is committed.
    """

    def __init__(self, store: RuntimeStore, policy: dict[str, Any], *, evidence_dir: str | pathlib.Path | None = None):
        self.store = store
        self.policy = policy
        self.policy_digest = digest_policy(policy)
        self.evidence_dir = pathlib.Path(evidence_dir) if evidence_dir is not None else None

    def authorize_task(self, task_id: str, lease_token: str) -> dict[str, Any]:
        try:
            return self._authorize_task(task_id, lease_token)
        except (AuthorizationDenied, InvalidTransition, LeaseConflict, RuntimeStoreError, ValueError, KeyError) as exc:
            # Persist expiry after the failed authorization transaction has rolled back.
            try:
                if "approval has expired" in str(exc):
                    with self.store._transaction() as conn:
                        row = conn.execute("SELECT id,job_id FROM approvals WHERE status='approved' AND expires_at<=? AND id IN (SELECT json_extract(input,'$.approval_id') FROM tasks WHERE id=?)", (time.time(), task_id)).fetchone()
                        if row:
                            conn.execute("UPDATE approvals SET status='expired' WHERE id=? AND status='approved'", (row["id"],))
                            self.store._event(conn, "approval_expired", job_id=row["job_id"], payload={"approval_id": row["id"]})
            except Exception:
                pass
            # Denials are durable audit events. Never include arguments or credentials.
            try:
                task = self.store.get_task(task_id)
                self.store._event_in_new_transaction(
                    "authorization_denied", job_id=task.get("job_id") if task else None,
                    task_id=task_id, payload={"reason_code": type(exc).__name__, "reason": str(exc)[:500]})
            except Exception:
                pass
            if isinstance(exc, AuthorizationDenied):
                raise
            raise AuthorizationDenied(str(exc)) from exc

    def _authorize_task(self, task_id: str, lease_token: str) -> dict[str, Any]:
        now = time.time()
        with self.store._transaction() as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise AuthorizationDenied("unknown task")
            lease = self.store._require_lease(conn, task_id, lease_token, now)
            if lease["status"] != "leased":
                raise AuthorizationDenied("task must be freshly claimed and not already running")
            if task["task_type"] != "tool_action":
                raise AuthorizationDenied("only tool_action tasks can enter the authorization gateway")
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (task["job_id"],)).fetchone()
            if not job or job["status"] not in {"queued", "running"} or job["cancelled_at"] is not None:
                raise AuthorizationDenied("assessment is missing, terminal or cancelled")
            if digest_policy(self.policy) != self.policy_digest or job["policy_digest"] != self.policy_digest:
                raise AuthorizationDenied("current validated policy does not match the assessment snapshot")

            try:
                payload = json.loads(task["input"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise AuthorizationDenied("task input is malformed") from exc
            required = {"target", "tool_name", "parameters", "approval_id", "action_id"}
            if not isinstance(payload, dict) or set(payload) != required:
                raise AuthorizationDenied("tool task input must contain exactly target, tool_name, parameters, approval_id and action_id")
            target, tool_name = payload["target"], payload["tool_name"]
            action_id, approval_id = payload["action_id"], payload["approval_id"]
            if not isinstance(action_id, str) or not _ACTION_ID.fullmatch(action_id):
                raise AuthorizationDenied("action_id is missing or malformed")
            if not isinstance(approval_id, str) or not approval_id:
                raise AuthorizationDenied("approval_id is missing")
            try:
                parameters = validate_tool_action(tool_name, payload["parameters"])
                definition = tool_definition(tool_name)
                validate_url(self.policy, target, parameters["method"], resolve_dns=False)
            except (ToolSchemaError, PolicyError, TypeError, KeyError) as exc:
                raise AuthorizationDenied(f"tool schema or target scope rejected: {exc}") from exc

            approval = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not approval:
                raise AuthorizationDenied("approval record does not exist")
            if approval["revoked_at"] is not None:
                raise AuthorizationDenied("approval has been revoked")
            if approval["status"] != "approved":
                raise AuthorizationDenied(f"approval is not approved: {approval['status']}")
            if approval["expires_at"] <= now:
                conn.execute("UPDATE approvals SET status='expired' WHERE id=? AND status='approved'", (approval_id,))
                self.store._event(conn, "approval_expired", job_id=job["id"], payload={"approval_id": approval_id})
                raise AuthorizationDenied("approval has expired")
            expected_approval_digest = action_digest(job_id=job["id"], target=target, tool_name=tool_name,
                                                     parameters=parameters, policy_digest=self.policy_digest)
            if approval["job_id"] != job["id"] or approval["action_digest"] != expected_approval_digest:
                raise AuthorizationDenied("action does not match the approved assessment, target, tool and arguments")
            if approval["policy_digest"] != self.policy_digest or approval["target"] != target or approval["tool_name"] != tool_name:
                raise AuthorizationDenied("approval policy or action metadata is inconsistent")
            if definition["approval_required"] and approval["status"] != "approved":
                raise AuthorizationDenied("registered tool requires human approval")

            # The digest includes the approval identity/expiry and unique execution identity,
            # in addition to all scope- and tool-sensitive values.
            authorization_digest = _canonical_digest({
                "assessment_id": job["id"], "job_id": job["id"], "task_id": task_id,
                "action_id": action_id, "scope_version": self.policy_digest,
                "target": target, "operation": parameters["method"],
                "tool_name": tool_name, "tool_version": definition["version"],
                "parameters": parameters, "policy_digest": self.policy_digest,
                "approval_id": approval_id, "approval_expires_at": approval["expires_at"],
            })
            existing = conn.execute("SELECT * FROM execution_attempts WHERE action_id=?", (action_id,)).fetchone()
            if existing:
                raise AuthorizationDenied("action_id has already been used; replay rejected")
            execution_id = "exec-" + uuid.uuid4().hex
            conn.execute("UPDATE approvals SET status='consumed',consumed_at=? WHERE id=? AND status='approved' AND revoked_at IS NULL",
                         (now, approval_id))
            conn.execute("INSERT INTO execution_attempts(id,action_id,job_id,task_id,worker_id,approval_id,authorization_digest,policy_digest,tool_name,tool_version,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'authorized',?,?)",
                         (execution_id, action_id, job["id"], task_id, lease["worker_id"], approval_id,
                          authorization_digest, self.policy_digest, tool_name, definition["version"], now, now))
            self.store._event(conn, "approval_consumed", job_id=job["id"], task_id=task_id,
                              payload={"approval_id": approval_id, "action_digest": approval["action_digest"]})
            self.store._event(conn, "authorization_allowed", job_id=job["id"], task_id=task_id,
                              payload={"execution_id": execution_id, "action_id": action_id,
                                       "authorization_digest": authorization_digest,
                                       "tool_name": tool_name, "tool_version": definition["version"],
                                       "scope_version": self.policy_digest})
            return {"execution_id": execution_id, "action_id": action_id, "state": "authorized",
                    "authorization_digest": authorization_digest, "tool_name": tool_name,
                    "tool_version": definition["version"], "policy_digest": self.policy_digest,
                    "approval_id": approval_id, "approval_expires_at": approval["expires_at"]}

    def _revalidate_execution_action(self, task, execution, approval) -> dict[str, Any]:
        """Recompute the full digest from current persisted action data at every transition."""
        try:
            payload = json.loads(task["input"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise AuthorizationDenied("persisted task action is malformed") from exc
        required = {"target", "tool_name", "parameters", "approval_id", "action_id"}
        if not isinstance(payload, dict) or set(payload) != required:
            raise AuthorizationDenied("persisted task action has missing or unexpected fields")
        if payload["action_id"] != execution["action_id"] or payload["approval_id"] != execution["approval_id"]:
            raise AuthorizationDenied("persisted action or approval identity changed")
        if approval["status"] != "consumed" or approval["revoked_at"] is not None:
            raise AuthorizationDenied("approval is not in the consumed, non-revoked state")
        if not isinstance(approval["expires_at"], (int, float)) or approval["expires_at"] <= time.time():
            raise AuthorizationDenied("approval expired before execution/result validation")
        try:
            parameters = validate_tool_action(payload["tool_name"], payload["parameters"])
            definition = tool_definition(payload["tool_name"])
            validate_url(self.policy, payload["target"], parameters["method"], resolve_dns=False)
        except (ToolSchemaError, PolicyError, TypeError, KeyError) as exc:
            raise AuthorizationDenied(f"persisted action no longer passes schema/scope validation: {exc}") from exc
        if payload["tool_name"] != execution["tool_name"] or definition["version"] != execution["tool_version"]:
            raise AuthorizationDenied("registered tool identity or version changed")
        if digest_policy(self.policy) != self.policy_digest or execution["policy_digest"] != self.policy_digest:
            raise AuthorizationDenied("policy snapshot changed")
        expected_approval = action_digest(job_id=execution["job_id"], target=payload["target"],
            tool_name=payload["tool_name"], parameters=parameters, policy_digest=self.policy_digest)
        if approval["action_digest"] != expected_approval or approval["policy_digest"] != self.policy_digest:
            raise AuthorizationDenied("persisted action no longer matches the approved action")
        expected = _canonical_digest({
            "assessment_id": execution["job_id"], "job_id": execution["job_id"], "task_id": task["id"],
            "action_id": payload["action_id"], "scope_version": self.policy_digest,
            "target": payload["target"], "operation": parameters["method"],
            "tool_name": payload["tool_name"], "tool_version": definition["version"],
            "parameters": parameters, "policy_digest": self.policy_digest,
            "approval_id": approval["id"], "approval_expires_at": approval["expires_at"],
        })
        if expected != execution["authorization_digest"]:
            raise AuthorizationDenied("authorization digest no longer matches current persisted action")
        return payload

    def begin_execution(self, execution_id: str, *, task_id: str, lease_token: str) -> dict[str, Any]:
        """Revalidate authority, then fail closed because no isolated backend is installed."""
        now = time.time()
        with self.store._transaction() as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise AuthorizationDenied("unknown task")
            lease = self.store._require_lease(conn, task_id, lease_token, now)
            row = conn.execute("SELECT * FROM execution_attempts WHERE id=? AND task_id=?", (execution_id, task_id)).fetchone()
            if not row or row["state"] != "authorized":
                raise AuthorizationDenied("execution is not in authorized state")
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (row["job_id"],)).fetchone()
            approval = conn.execute("SELECT * FROM approvals WHERE id=?", (row["approval_id"],)).fetchone()
            if not job or job["status"] not in {"queued", "running"} or job["cancelled_at"] is not None:
                conn.execute("UPDATE execution_attempts SET state='cancelled',updated_at=?,finished_at=?,error_code='job_cancelled' WHERE id=?", (now, now, execution_id))
                self.store._event(conn, "execution_blocked", job_id=row["job_id"], task_id=task_id,
                                  payload={"execution_id": execution_id, "reason_code": "job_cancelled"})
                return {"execution_id": execution_id, "state": "cancelled"}
            if digest_policy(self.policy) != self.policy_digest or job["policy_digest"] != self.policy_digest or row["policy_digest"] != self.policy_digest:
                conn.execute("UPDATE execution_attempts SET state='blocked',updated_at=?,finished_at=?,error_code='policy_changed' WHERE id=?", (now, now, execution_id))
                conn.execute("UPDATE tasks SET status='blocked',error='policy changed before execution',updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?", (now, now, task_id))
                self.store._refresh_job_tx(conn, row["job_id"], now)
                self.store._event(conn, "execution_blocked", job_id=row["job_id"], task_id=task_id,
                                  payload={"execution_id": execution_id, "reason_code": "policy_changed"})
                return {"execution_id": execution_id, "state": "blocked", "reason": "policy_changed"}
            if task["status"] != "leased" or lease["worker_id"] != row["worker_id"]:
                conn.execute("UPDATE execution_attempts SET state='blocked',updated_at=?,finished_at=?,error_code='lease_state_mismatch' WHERE id=?", (now, now, execution_id))
                conn.execute("UPDATE tasks SET status='blocked',error='lease state mismatch before execution',updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?", (now, now, task_id))
                self.store._refresh_job_tx(conn, row["job_id"], now)
                self.store._event(conn, "execution_blocked", job_id=row["job_id"], task_id=task_id,
                                  payload={"execution_id": execution_id, "reason_code": "lease_state_mismatch"})
                return {"execution_id": execution_id, "state": "blocked", "reason": "lease_state_mismatch"}
            if (not approval or approval["status"] != "consumed" or approval["revoked_at"] is not None
                    or approval["expires_at"] <= now):
                conn.execute("UPDATE execution_attempts SET state='blocked',updated_at=?,finished_at=?,error_code='approval_stale_or_revoked' WHERE id=?", (now, now, execution_id))
                conn.execute("UPDATE tasks SET status='blocked',error='approval expired or revoked before execution',updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?", (now, now, task_id))
                self.store._refresh_job_tx(conn, row["job_id"], now)
                self.store._event(conn, "execution_blocked", job_id=row["job_id"], task_id=task_id,
                                  payload={"execution_id": execution_id, "reason_code": "approval_stale_or_revoked"})
                return {"execution_id": execution_id, "state": "blocked", "reason": "approval_stale_or_revoked"}
            try:
                self._revalidate_execution_action(task, row, approval)
            except AuthorizationDenied as exc:
                conn.execute("UPDATE execution_attempts SET state='blocked',updated_at=?,finished_at=?,error_code='action_changed' WHERE id=?", (now, now, execution_id))
                conn.execute("UPDATE tasks SET status='blocked',error='action changed after authorization',updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?", (now, now, task_id))
                self.store._refresh_job_tx(conn, row["job_id"], now)
                self.store._event(conn, "execution_blocked", job_id=row["job_id"], task_id=task_id,
                                  payload={"execution_id": execution_id, "reason_code": "action_changed"})
                return {"execution_id": execution_id, "state": "blocked", "reason": str(exc)[:300]}
            # No supervisor currently attests to container/process isolation, timeout,
            # filesystem restrictions or default-deny egress. Never start a handler in-process.
            conn.execute("UPDATE execution_attempts SET state='blocked',updated_at=?,finished_at=?,error_code='isolated_backend_unavailable' WHERE id=? AND state='authorized'", (now, now, execution_id))
            conn.execute("UPDATE tasks SET status='blocked',error='isolated execution backend unavailable',updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=? AND status='leased'", (now, now, task_id))
            self.store._refresh_job_tx(conn, row["job_id"], now)
            self.store._event(conn, "execution_blocked", job_id=row["job_id"], task_id=task_id,
                              payload={"execution_id": execution_id, "reason_code": "isolated_backend_unavailable"})
            return {"execution_id": execution_id, "state": "blocked", "reason": "isolated_backend_unavailable"}
    def _find_durable_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        if self.evidence_dir is None or not isinstance(evidence_id, str) or not evidence_id:
            return None
        if self.evidence_dir.is_symlink() or not self.evidence_dir.is_dir():
            return None
        path = self.evidence_dir / "evidence.jsonl"
        if path.is_symlink() or not path.exists():
            return None
        try:
            file_stat = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 64 * 1024 * 1024:
                return None
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                for line in stream:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        return None
                    if record.get("evidence_id") == evidence_id and isinstance(record.get("response"), dict):
                        return record
        except (OSError, UnicodeError, TypeError):
            return None
        return None

    def complete_execution(self, execution_id: str, *, task_id: str, lease_token: str,
                           result: dict[str, Any]) -> dict[str, Any]:
        """Commit completion only when the result references persisted evidence."""
        if not isinstance(result, dict) or not isinstance(result.get("evidence_id"), str):
            raise AuthorizationDenied("completion requires a result object with evidence_id")
        evidence_record = self._find_durable_evidence(result["evidence_id"])
        if not evidence_record:
            raise AuthorizationDenied("completion evidence is missing, malformed or not durably persisted")
        safe_result = redact_payload(result)
        result_digest = _canonical_digest(safe_result)
        now = time.time()
        with self.store._transaction() as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise AuthorizationDenied("unknown task")
            self.store._require_lease(conn, task_id, lease_token, now)
            execution = conn.execute("SELECT * FROM execution_attempts WHERE id=? AND task_id=?", (execution_id, task_id)).fetchone()
            if not execution or execution["state"] != "running" or task["status"] != "running":
                raise AuthorizationDenied("only a running authorized execution can complete")
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (execution["job_id"],)).fetchone()
            approval = conn.execute("SELECT * FROM approvals WHERE id=?", (execution["approval_id"],)).fetchone()
            if not job or job["status"] == "cancelled" or job["cancelled_at"] is not None:
                raise AuthorizationDenied("cancelled assessment cannot commit a result")
            if digest_policy(self.policy) != self.policy_digest or job["policy_digest"] != self.policy_digest or execution["policy_digest"] != self.policy_digest:
                raise AuthorizationDenied("policy changed before result commit")
            if (not approval or approval["status"] != "consumed" or approval["revoked_at"] is not None
                    or approval["expires_at"] <= now):
                raise AuthorizationDenied("approval was expired, revoked or not consumed before result commit")
            action = self._revalidate_execution_action(task, execution, approval)
            evidence_request = evidence_record.get("request") if isinstance(evidence_record, dict) else None
            if (not isinstance(evidence_request, dict) or evidence_request.get("url") != action.get("target")
                    or evidence_request.get("method") != action.get("parameters", {}).get("method")
                    or evidence_request.get("action_id") != action.get("action_id")):
                raise AuthorizationDenied("evidence does not match this action identity, target and operation")
            conn.execute("UPDATE execution_attempts SET state='completed',updated_at=?,finished_at=?,result_digest=? WHERE id=? AND state='running'",
                         (now, now, result_digest, execution_id))
            conn.execute("UPDATE tasks SET status='complete',result=?,error=NULL,updated_at=?,finished_at=?,lease_token=NULL,lease_expires_at=NULL WHERE id=? AND status='running'",
                         (json.dumps(safe_result, sort_keys=True, separators=(",", ":"), ensure_ascii=False), now, now, task_id))
            self.store._event(conn, "execution_completed", job_id=execution["job_id"], task_id=task_id,
                              payload={"execution_id": execution_id, "result_digest": result_digest,
                                       "evidence_id": result["evidence_id"]})
            self.store._event(conn, "task_completed", job_id=execution["job_id"], task_id=task_id,
                              payload={"execution_id": execution_id, "evidence_id": result["evidence_id"]})
            self.store._refresh_job_tx(conn, execution["job_id"], now)
            return {"execution_id": execution_id, "state": "completed", "result_digest": result_digest,
                    "task_id": task_id, "task_status": "complete", "evidence_id": result["evidence_id"]}

    def fail_execution(self, execution_id: str, *, task_id: str, lease_token: str,
                       error_code: str) -> dict[str, Any]:
        """Fail closed after a consumed approval; authorized actions are never auto-replayed."""
        if not isinstance(error_code, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", error_code):
            raise ValueError("error_code must be a short stable identifier")
        now = time.time()
        with self.store._transaction() as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise AuthorizationDenied("unknown task")
            self.store._require_lease(conn, task_id, lease_token, now)
            execution = conn.execute("SELECT * FROM execution_attempts WHERE id=? AND task_id=?", (execution_id, task_id)).fetchone()
            if not execution or execution["state"] not in {"authorized", "running"}:
                raise AuthorizationDenied("execution is not active")
            conn.execute("UPDATE execution_attempts SET state='failed',updated_at=?,finished_at=?,error_code=? WHERE id=?",
                         (now, now, error_code, execution_id))
            conn.execute("UPDATE tasks SET status='failed',error=?,updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?",
                         (error_code, now, now, task_id))
            self.store._event(conn, "execution_failed", job_id=execution["job_id"], task_id=task_id,
                              payload={"execution_id": execution_id, "reason_code": error_code})
            self.store._event(conn, "task_failed", job_id=execution["job_id"], task_id=task_id,
                              payload={"reason_code": error_code, "retryable": False})
            self.store._refresh_job_tx(conn, execution["job_id"], now)
            return {"execution_id": execution_id, "state": "failed", "task_status": "failed", "error_code": error_code}

