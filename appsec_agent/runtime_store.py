"""Transactional SQLite job/task store for resumable ARTEMIS runtime work.

This module intentionally stores task metadata and lifecycle events only. It does
not execute tools; authorization must still be checked immediately before any
network or scanner action.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sqlite3
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

from .evidence import redact_payload, redact_text, redact_url

SCHEMA_VERSION = 3
JOB_STATES = {"queued", "running", "complete", "failed", "cancelled"}
TASK_STATES = {"pending", "leased", "running", "complete", "failed", "cancelled", "blocked"}
TERMINAL_TASK_STATES = {"complete", "failed", "cancelled", "blocked"}


class RuntimeStoreError(RuntimeError):
    """Base error for runtime persistence operations."""


class LeaseConflict(RuntimeStoreError):
    """A worker attempted to mutate a task without its current lease token."""


class InvalidTransition(RuntimeStoreError):
    """A requested job/task lifecycle transition is not allowed."""


def _now() -> float:
    return time.time()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def policy_digest(policy: dict[str, Any]) -> str:
    """Return a stable digest for a validated policy object."""
    if not isinstance(policy, dict) or not policy:
        raise ValueError("policy must be a non-empty object")
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _decode(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    for key in ("metadata", "result", "payload"):
        if key in result and result[key] is not None:
            result[key] = json.loads(result[key])
    return result


def _audit_safe_payload(value, key=""):
    """Redact event payloads, including credential-bearing URLs and free text."""
    if isinstance(value, dict):
        return {str(k): _audit_safe_payload(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_audit_safe_payload(v) for v in value]
    if isinstance(value, str):
        if key.lower() in {"target", "url", "action_target"}:
            return redact_url(value)[:4096]
        return redact_text(value)[:2000]
    return value


class RuntimeStore:
    """SQLite-backed jobs, dependency-aware tasks, leases, retries and audit events.

    Every mutating operation uses ``BEGIN IMMEDIATE`` so competing local workers
    serialize around claims and state transitions. SQLite is suitable for a
    single host and a modest worker pool; use PostgreSQL for multi-host dispatch.
    """

    def __init__(self, path: str | os.PathLike[str], *, busy_timeout_ms: int = 5000):
        self.path = pathlib.Path(path)
        if self.path.is_symlink():
            raise ValueError("runtime database path must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.busy_timeout_ms = max(100, min(int(busy_timeout_ms), 120_000))
        # Process-local callbacks are deliberately not persisted. A worker process
        # must re-register its supervisor after startup; otherwise cancellation of
        # a durable running execution fails closed rather than claiming success.
        self._execution_cancellers: list[Callable[[str], bool]] = []
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=self.busy_timeout_ms / 1000, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def register_execution_canceller(self, callback: Callable[[str], bool]) -> None:
        """Register a supervisor callback that terminates a durable execution ID.

        The callback must return True only after termination has been confirmed.
        A missing callback intentionally prevents cancellation from being
        acknowledged for executions persisted as running.
        """
        if not callable(callback):
            raise TypeError("execution canceller must be callable")
        if callback not in self._execution_cancellers:
            self._execution_cancellers.append(callback)

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _transaction(self):
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS runtime_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    idempotency_key TEXT UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('queued','running','complete','failed','cancelled')),
                    policy_digest TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    cancelled_at REAL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    task_key TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','leased','running','complete','failed','cancelled','blocked')),
                    priority INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 2 CHECK(max_attempts BETWEEN 1 AND 100),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    worker_id TEXT,
                    lease_token TEXT,
                    lease_expires_at REAL,
                    heartbeat_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    started_at REAL,
                    finished_at REAL,
                    input TEXT NOT NULL DEFAULT '{}',
                    result TEXT,
                    error TEXT,
                    UNIQUE(job_id, task_key)
                );
                CREATE TABLE IF NOT EXISTS task_dependencies (
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    depends_on_task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    PRIMARY KEY(task_id, depends_on_task_id),
                    CHECK(task_id <> depends_on_task_id)
                );
                CREATE TABLE IF NOT EXISTS runtime_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT REFERENCES jobs(id) ON DELETE CASCADE,
                    task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    at REAL NOT NULL,
                    payload TEXT NOT NULL DEFAULT '{}',
                    prev_hash TEXT,
                    event_hash TEXT
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    action_digest TEXT NOT NULL,
                    target TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    parameter_keys TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','consumed','expired')),
                    requested_by TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    decided_at REAL,
                    decided_by TEXT,
                    decision_reason TEXT,
                    consumed_at REAL,
                    revoked_at REAL,
                    revoked_by TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_approvals_job_status ON approvals(job_id,status,created_at);
                CREATE TABLE IF NOT EXISTS execution_attempts (
                    id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    worker_id TEXT NOT NULL,
                    approval_id TEXT NOT NULL REFERENCES approvals(id),
                    authorization_digest TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    tool_version TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','claimed','authorized','running','completed','failed','cancelled','blocked','recovery_required')),
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    started_at REAL,
                    finished_at REAL,
                    result_digest TEXT,
                    error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_execution_task ON execution_attempts(task_id,state);
                CREATE INDEX IF NOT EXISTS idx_tasks_claim ON tasks(status, priority DESC, created_at);
                CREATE INDEX IF NOT EXISTS idx_tasks_job ON tasks(job_id, status);
                CREATE INDEX IF NOT EXISTS idx_tasks_lease ON tasks(status, lease_expires_at);
                CREATE INDEX IF NOT EXISTS idx_task_deps_dep ON task_dependencies(depends_on_task_id);
                CREATE INDEX IF NOT EXISTS idx_events_job ON runtime_events(job_id, id);
            """)
            current = conn.execute("SELECT value FROM runtime_meta WHERE key='schema_version'").fetchone()
            schema_before = int(current[0]) if current else 0
            if current and schema_before > SCHEMA_VERSION:
                raise RuntimeStoreError(f"Runtime DB schema {current[0]} is newer than supported {SCHEMA_VERSION}")
            event_cols = {r[1] for r in conn.execute("PRAGMA table_info(runtime_events)")}
            needs_anchor = "prev_hash" not in event_cols or "event_hash" not in event_cols
            if "prev_hash" not in event_cols:
                conn.execute("ALTER TABLE runtime_events ADD COLUMN prev_hash TEXT")
            if "event_hash" not in event_cols:
                conn.execute("ALTER TABLE runtime_events ADD COLUMN event_hash TEXT")
            approval_cols = {r[1] for r in conn.execute("PRAGMA table_info(approvals)")}
            if "revoked_at" not in approval_cols:
                conn.execute("ALTER TABLE approvals ADD COLUMN revoked_at REAL")
            if "revoked_by" not in approval_cols:
                conn.execute("ALTER TABLE approvals ADD COLUMN revoked_by TEXT")
            # Anchor legacy events into a new integrity chain at migration time.
            # This protects subsequent modifications; it cannot attest to pre-migration history.
            if needs_anchor:
                previous = "0" * 64
                for row in conn.execute("SELECT id,job_id,task_id,event_type,at,payload FROM runtime_events ORDER BY id").fetchall():
                    payload = {"id": row["id"], "job_id": row["job_id"], "task_id": row["task_id"],
                               "event_type": row["event_type"], "at": row["at"], "payload": row["payload"],
                               "prev_hash": previous}
                    digest = hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()
                    conn.execute("UPDATE runtime_events SET prev_hash=?,event_hash=? WHERE id=?", (previous, digest, row["id"]))
                    previous = digest
            head_row = conn.execute("SELECT event_hash FROM runtime_events ORDER BY id DESC LIMIT 1").fetchone()
            head = head_row[0] if head_row and head_row[0] else "0" * 64
            existing_head = conn.execute("SELECT value FROM runtime_meta WHERE key='audit_head'").fetchone()
            if current is None or schema_before < 3 or needs_anchor:
                conn.execute("INSERT INTO runtime_meta(key,value) VALUES('audit_head',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (head,))
            conn.execute("INSERT INTO runtime_meta(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SCHEMA_VERSION),))
        for private_path in (self.path, pathlib.Path(str(self.path) + "-wal"), pathlib.Path(str(self.path) + "-shm")):
            try:
                if private_path.exists() and not private_path.is_symlink():
                    os.chmod(private_path, 0o600)
            except OSError:
                pass

    @staticmethod
    def _event(conn, event_type: str, *, job_id: str | None = None, task_id: str | None = None, payload=None):
        """Append a redacted, hash-chained event within the caller's transaction."""
        safe = _audit_safe_payload(payload or {})
        at = _now()
        prior = conn.execute("SELECT event_hash FROM runtime_events ORDER BY id DESC LIMIT 1").fetchone()
        previous = prior[0] if prior and prior[0] else "0" * 64
        encoded = _json(safe)
        cur = conn.execute("INSERT INTO runtime_events(job_id,task_id,event_type,at,payload,prev_hash,event_hash) VALUES(?,?,?,?,?,?,NULL)",
                           (job_id, task_id, event_type, at, encoded, previous))
        event_id = cur.lastrowid
        material = {"id": event_id, "job_id": job_id, "task_id": task_id, "event_type": event_type,
                    "at": at, "payload": encoded, "prev_hash": previous}
        digest = hashlib.sha256(_json(material).encode("utf-8")).hexdigest()
        conn.execute("UPDATE runtime_events SET event_hash=? WHERE id=?", (digest, event_id))
        conn.execute("INSERT INTO runtime_meta(key,value) VALUES('audit_head',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (digest,))

    def _event_in_new_transaction(self, event_type: str, *, job_id: str | None = None,
                                  task_id: str | None = None, payload=None) -> None:
        with self._transaction() as conn:
            self._event(conn, event_type, job_id=job_id, task_id=task_id, payload=payload)

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify event ordering, previous links and row hashes from the migration anchor."""
        previous = "0" * 64
        count = 0
        with self._connection() as conn:
            rows = conn.execute("SELECT id,job_id,task_id,event_type,at,payload,prev_hash,event_hash FROM runtime_events ORDER BY id").fetchall()
            head_row = conn.execute("SELECT value FROM runtime_meta WHERE key='audit_head'").fetchone()
        for row in rows:
            material = {"id": row["id"], "job_id": row["job_id"], "task_id": row["task_id"],
                        "event_type": row["event_type"], "at": row["at"], "payload": row["payload"],
                        "prev_hash": previous}
            expected = hashlib.sha256(_json(material).encode("utf-8")).hexdigest()
            if row["prev_hash"] != previous or row["event_hash"] != expected:
                return {"valid": False, "checked_events": count, "failed_event_id": row["id"]}
            previous = expected
            count += 1
        stored_head = head_row[0] if head_row else "0" * 64
        if stored_head != previous:
            return {"valid": False, "checked_events": count, "failed_event_id": None, "reason": "audit head mismatch"}
        return {"valid": True, "checked_events": count, "head": previous}

    def create_job(self, *, policy_digest: str, metadata=None, idempotency_key: str | None = None) -> dict[str, Any]:
        if not isinstance(policy_digest, str) or not policy_digest.strip() or len(policy_digest) > 256:
            raise ValueError("policy_digest must be a non-empty string of at most 256 characters")
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key) > 256):
            raise ValueError("idempotency_key must be a non-empty string of at most 256 characters")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        now = _now()
        with self._transaction() as conn:
            if idempotency_key:
                existing = conn.execute("SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                if existing:
                    if existing["policy_digest"] != policy_digest:
                        raise RuntimeStoreError("idempotency key already exists with a different policy digest")
                    return _decode(existing)
            job_id = "job-" + uuid.uuid4().hex
            conn.execute("INSERT INTO jobs(id,idempotency_key,status,policy_digest,created_at,updated_at,metadata) VALUES(?,?,?,?,?,?,?)",
                         (job_id, idempotency_key, "queued", policy_digest, now, now, _json(redact_payload(metadata or {}))))
            self._event(conn, "job_created", job_id=job_id, payload={"policy_digest": policy_digest})
            return _decode(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def add_task(self, job_id: str, task_key: str, task_type: str, *, input=None, dependencies=(), priority: int = 0,
                 max_attempts: int = 2) -> dict[str, Any]:
        for label, value in (("task_key", task_key), ("task_type", task_type)):
            if not isinstance(value, str) or not value.strip() or len(value) > 200:
                raise ValueError(f"{label} must be a non-empty string of at most 200 characters")
        if input is not None and not isinstance(input, dict):
            raise ValueError("task input must be an object")
        if not isinstance(priority, int) or isinstance(priority, bool) or not -100000 <= priority <= 100000:
            raise ValueError("priority must be an integer between -100000 and 100000")
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or not 1 <= max_attempts <= 100:
            raise ValueError("max_attempts must be an integer between 1 and 100")
        deps = list(dict.fromkeys(dependencies))
        now = _now()
        with self._transaction() as conn:
            job = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                raise KeyError(f"unknown job: {job_id}")
            if job["status"] in {"complete", "failed", "cancelled"}:
                raise InvalidTransition("cannot add tasks to a terminal job")
            existing = conn.execute("SELECT * FROM tasks WHERE job_id=? AND task_key=?", (job_id, task_key)).fetchone()
            if existing:
                expected = (task_type, _json(redact_payload(input or {})), priority, max_attempts)
                actual = (existing["task_type"], existing["input"], existing["priority"], existing["max_attempts"])
                if actual != expected:
                    raise RuntimeStoreError("task_key already exists with different task parameters")
                task_id = existing["id"]
            else:
                task_id = "task-" + uuid.uuid4().hex
                conn.execute("INSERT INTO tasks(id,job_id,task_key,task_type,status,priority,max_attempts,created_at,updated_at,input) VALUES(?,?,?,?,?,?,?,?,?,?)",
                             (task_id, job_id, task_key, task_type, "pending", priority, max_attempts, now, now, _json(redact_payload(input or {}))))
                self._event(conn, "task_created", job_id=job_id, task_id=task_id, payload={"task_key": task_key, "task_type": task_type})
            for dep in deps:
                dep_row = conn.execute("SELECT job_id FROM tasks WHERE id=?", (dep,)).fetchone()
                if not dep_row or dep_row["job_id"] != job_id:
                    raise ValueError("dependencies must reference tasks in the same job")
                if dep == task_id:
                    raise ValueError("task cannot depend on itself")
                conn.execute("INSERT OR IGNORE INTO task_dependencies(task_id,depends_on_task_id) VALUES(?,?)", (task_id, dep))
            # Reject dependency cycles, including cycles introduced by adding dependencies later.
            cycle = conn.execute("""WITH RECURSIVE walk(origin,node) AS (
                SELECT task_id, depends_on_task_id FROM task_dependencies
                UNION ALL SELECT walk.origin, d.depends_on_task_id FROM walk JOIN task_dependencies d ON d.task_id=walk.node
            ) SELECT 1 FROM walk WHERE origin=node LIMIT 1""").fetchone()
            if cycle:
                raise ValueError("task dependency cycle detected")
            conn.execute("UPDATE jobs SET updated_at=?,status=CASE WHEN status='queued' THEN 'running' ELSE status END WHERE id=?", (now, job_id))
            return _decode(conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())

    def claim_next(self, worker_id: str, *, expected_policy_digest: str, lease_seconds: int = 60, job_id: str | None = None, task_type: str | None = None) -> dict[str, Any] | None:
        if not isinstance(expected_policy_digest, str) or not expected_policy_digest.strip() or len(expected_policy_digest) > 256:
            raise ValueError("expected_policy_digest must be a non-empty string of at most 256 characters")
        if not isinstance(worker_id, str) or not worker_id.strip() or len(worker_id) > 200:
            raise ValueError("worker_id must be a non-empty string of at most 200 characters")
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or not 5 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be an integer between 5 and 3600")
        now = _now()
        with self._transaction() as conn:
            recovered = self._recover_expired_tx(conn, now)
            if recovered["retried"] or recovered["failed"]:
                affected = conn.execute("SELECT DISTINCT job_id FROM tasks WHERE status IN ('pending','failed','complete','blocked','cancelled')").fetchall()
                for affected_job in affected:
                    self._refresh_job_tx(conn, affected_job["job_id"], now)
            self._block_failed_dependencies_tx(conn, now, job_id=job_id)
            if job_id:
                job = conn.execute("SELECT policy_digest,status FROM jobs WHERE id=?", (job_id,)).fetchone()
                if not job:
                    raise KeyError(f"unknown job: {job_id}")
                if job["policy_digest"] != expected_policy_digest:
                    raise RuntimeStoreError("worker policy digest does not match queued job policy")
            sql = """SELECT t.* FROM tasks t JOIN jobs j ON j.id=t.job_id
                WHERE t.status='pending' AND j.status IN ('queued','running') AND j.cancelled_at IS NULL
                  AND j.policy_digest=?
                AND NOT EXISTS (SELECT 1 FROM task_dependencies d JOIN tasks p ON p.id=d.depends_on_task_id
                                WHERE d.task_id=t.id AND p.status <> 'complete')"""
            params: list[Any] = [expected_policy_digest]
            if job_id:
                sql += " AND t.job_id=?"; params.append(job_id)
            if task_type is not None:
                if not isinstance(task_type, str) or not task_type or len(task_type) > 100:
                    raise ValueError("task_type must be a non-empty string of at most 100 characters")
                sql += " AND t.task_type=?"; params.append(task_type)
            sql += " ORDER BY t.priority DESC,t.created_at,t.id LIMIT 1"
            row = conn.execute(sql, params).fetchone()
            if not row:
                return None
            token = uuid.uuid4().hex
            conn.execute("UPDATE tasks SET status='leased',worker_id=?,lease_token=?,lease_expires_at=?,heartbeat_at=?,attempts=attempts+1,updated_at=? WHERE id=? AND status='pending'",
                         (worker_id, token, now + lease_seconds, now, now, row["id"]))
            conn.execute("UPDATE jobs SET status='running',updated_at=? WHERE id=? AND status='queued'", (now, row["job_id"]))
            self._event(conn, "task_leased", job_id=row["job_id"], task_id=row["id"], payload={"worker_id": worker_id, "lease_seconds": lease_seconds})
            return _decode(conn.execute("SELECT * FROM tasks WHERE id=?", (row["id"],)).fetchone())

    def start_task(self, task_id: str, lease_token: str) -> dict[str, Any]:
        now = _now()
        with self._transaction() as conn:
            row = self._require_lease(conn, task_id, lease_token, now)
            if row["task_type"] == "tool_action":
                raise InvalidTransition("tool_action tasks must enter running through AuthorizationGateway")
            if row["status"] not in {"leased", "running"}:
                raise InvalidTransition(f"cannot start task from {row['status']}")
            conn.execute("UPDATE tasks SET status='running',updated_at=?,heartbeat_at=?,started_at=COALESCE(started_at,?) WHERE id=?", (now, now, now, task_id))
            self._event(conn, "task_started", job_id=row["job_id"], task_id=task_id, payload={"worker_id": row["worker_id"]})
            return _decode(conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())

    def heartbeat(self, task_id: str, lease_token: str, *, lease_seconds: int = 60) -> float:
        if not isinstance(lease_seconds, int) or isinstance(lease_seconds, bool) or not 5 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be an integer between 5 and 3600")
        now = _now()
        with self._transaction() as conn:
            row = self._require_lease(conn, task_id, lease_token, now)
            if row["status"] not in {"leased", "running"}:
                raise InvalidTransition(f"cannot heartbeat task from {row['status']}")
            expiry = now + lease_seconds
            conn.execute("UPDATE tasks SET lease_expires_at=?,heartbeat_at=?,updated_at=? WHERE id=?", (expiry, now, now, task_id))
            self._event(conn, "task_heartbeat", job_id=row["job_id"], task_id=task_id, payload={"lease_expires_at": expiry})
            return expiry

    def complete_task(self, task_id: str, lease_token: str, *, result=None) -> dict[str, Any]:
        if result is not None and not isinstance(result, dict):
            raise ValueError("task result must be an object")
        now = _now()
        with self._transaction() as conn:
            row = self._require_lease(conn, task_id, lease_token, now)
            if row["task_type"] == "tool_action":
                raise InvalidTransition("tool_action tasks require AuthorizationGateway and durable evidence to complete")
            if row["status"] not in {"leased", "running"}:
                raise InvalidTransition(f"cannot complete task from {row['status']}")
            conn.execute("UPDATE tasks SET status='complete',result=?,error=NULL,updated_at=?,finished_at=?,lease_token=NULL,lease_expires_at=NULL WHERE id=?",
                         (_json(redact_payload(result or {})), now, now, task_id))
            self._event(conn, "task_completed", job_id=row["job_id"], task_id=task_id)
            self._refresh_job_tx(conn, row["job_id"], now)
            return _decode(conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())

    def fail_task(self, task_id: str, lease_token: str, error: str, *, retryable: bool = True) -> dict[str, Any]:
        if not isinstance(error, str) or not error.strip():
            raise ValueError("error must be a non-empty string")
        now = _now()
        with self._transaction() as conn:
            row = self._require_lease(conn, task_id, lease_token, now)
            if row["status"] not in {"leased", "running"}:
                raise InvalidTransition(f"cannot fail task from {row['status']}")
            retry = bool(retryable and row["attempts"] < row["max_attempts"])
            state = "pending" if retry else "failed"
            conn.execute("UPDATE tasks SET status=?,error=?,updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?",
                         (state, error[:4000], now, None if retry else now, task_id))
            self._event(conn, "task_retry_scheduled" if retry else "task_failed", job_id=row["job_id"], task_id=task_id,
                        payload={"retryable": bool(retryable), "attempts": row["attempts"], "error": error[:500]})
            self._refresh_job_tx(conn, row["job_id"], now)
            return _decode(conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())

    def cancel_job(self, job_id: str, *, reason: str = "operator request") -> dict[str, Any]:
        now = _now()
        unconfirmed_execution: str | None = None
        try:
            with self._transaction() as conn:
                job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                if not job:
                    raise KeyError(f"unknown job: {job_id}")
                if job["status"] in {"complete", "failed", "cancelled"}:
                    return _decode(job)
                # Terminate running containers before committing durable cancellation.
                # Hold the write transaction so another worker cannot claim/reassign
                # these tasks while termination is being confirmed. If no supervisor
                # confirms every execution, rollback the state transition.
                active = conn.execute(
                    "SELECT id FROM execution_attempts WHERE job_id=? AND state='running' ORDER BY id", (job_id,)
                ).fetchall()
                for execution in active:
                    terminated = False
                    for canceller in tuple(self._execution_cancellers):
                        try:
                            if canceller(execution["id"]):
                                terminated = True
                                break
                        except Exception:
                            # Cancellation is a security boundary; do not convert a
                            # runtime failure into a successful durable cancellation.
                            continue
                    if not terminated:
                        unconfirmed_execution = execution["id"]
                        raise InvalidTransition(
                            f"cannot acknowledge job cancellation: termination unconfirmed for execution {execution['id']}"
                        )
                    self._event(conn, "execution_terminated_for_cancellation", job_id=job_id,
                                payload={"execution_id": execution["id"]})
                conn.execute("UPDATE jobs SET status='cancelled',cancelled_at=?,updated_at=? WHERE id=?", (now, now, job_id))
                conn.execute("UPDATE tasks SET status='cancelled',updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE job_id=? AND status IN ('pending','leased','running')", (now, now, job_id))
                conn.execute("UPDATE execution_attempts SET state='cancelled',updated_at=?,finished_at=?,error_code='job_cancelled' WHERE job_id=? AND state IN ('pending','claimed','authorized','running')", (now, now, job_id))
                self._event(conn, "job_cancelled", job_id=job_id, payload={"reason": reason[:1000]})
                return _decode(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())
        except InvalidTransition:
            # The failed transition rolled back; record the denial independently.
            if unconfirmed_execution:
                try:
                    self._event_in_new_transaction("job_cancellation_unconfirmed", job_id=job_id,
                        payload={"execution_id": unconfirmed_execution, "reason_code": "termination_unconfirmed"})
                except Exception:
                    pass
            raise

    def recover_expired(self) -> dict[str, int]:
        now = _now()
        with self._transaction() as conn:
            counts = self._recover_expired_tx(conn, now)
            self._block_failed_dependencies_tx(conn, now)
            for row in conn.execute("SELECT DISTINCT job_id FROM tasks WHERE status IN ('pending','failed','complete','blocked','cancelled')").fetchall():
                self._refresh_job_tx(conn, row["job_id"], now)
            return counts

    def _recover_expired_tx(self, conn: sqlite3.Connection, now: float) -> dict[str, int]:
        rows = conn.execute("SELECT * FROM tasks WHERE status IN ('leased','running') AND lease_expires_at < ?", (now,)).fetchall()
        counts = {"retried": 0, "failed": 0}
        for row in rows:
            active_execution = conn.execute("SELECT id FROM execution_attempts WHERE task_id=? AND state IN ('authorized','running') LIMIT 1", (row["id"],)).fetchone()
            # A consumed approval cannot be blindly replayed after worker loss.
            retry = row["attempts"] < row["max_attempts"] and active_execution is None
            status = "pending" if retry else "failed"
            error = "worker lease expired" if active_execution is None else "execution lease expired after authorization; manual recovery required"
            conn.execute("UPDATE tasks SET status=?,error=?,updated_at=?,finished_at=?,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?",
                         (status, error, now, None if retry else now, row["id"]))
            if active_execution is not None:
                conn.execute("UPDATE execution_attempts SET state='recovery_required',updated_at=?,finished_at=?,error_code='lease_expired_after_authorization' WHERE id=?", (now, now, active_execution["id"]))
                self._event(conn, "execution_recovery_required", job_id=row["job_id"], task_id=row["id"],
                            payload={"execution_id": active_execution["id"], "reason_code": "lease_expired_after_authorization"})
            self._event(conn, "task_lease_expired_retry" if retry else "task_lease_expired_failed", job_id=row["job_id"], task_id=row["id"], payload={"attempts": row["attempts"]})
            counts["retried" if retry else "failed"] += 1
        return counts

    def _block_failed_dependencies_tx(self, conn: sqlite3.Connection, now: float, *, job_id: str | None = None) -> int:
        """Mark tasks blocked when any prerequisite is terminal but unsuccessful."""
        blocked_total = 0
        while True:
            sql = """SELECT DISTINCT t.id,t.job_id FROM tasks t
                JOIN task_dependencies d ON d.task_id=t.id
                JOIN tasks p ON p.id=d.depends_on_task_id
                JOIN jobs j ON j.id=t.job_id
                WHERE t.status='pending' AND p.status IN ('failed','blocked','cancelled')
                  AND j.status <> 'cancelled'"""
            params: list[Any] = []
            if job_id:
                sql += " AND t.job_id=?"; params.append(job_id)
            rows = conn.execute(sql, params).fetchall()
            if not rows:
                return blocked_total
            for row in rows:
                conn.execute("UPDATE tasks SET status='blocked',error=?,updated_at=?,finished_at=? WHERE id=? AND status='pending'",
                             ("dependency did not complete successfully", now, now, row["id"]))
                self._event(conn, "task_blocked_dependency", job_id=row["job_id"], task_id=row["id"])
                blocked_total += 1
                self._refresh_job_tx(conn, row["job_id"], now)

    def _require_lease(self, conn: sqlite3.Connection, task_id: str, token: str, now: float):
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown task: {task_id}")
        job = conn.execute("SELECT status FROM jobs WHERE id=?", (row["job_id"],)).fetchone()
        if job["status"] == "cancelled":
            raise InvalidTransition("job has been cancelled")
        if not token or row["lease_token"] != token or row["lease_expires_at"] is None or row["lease_expires_at"] < now:
            raise LeaseConflict("task lease is missing, expired, or belongs to another worker")
        return row

    def _refresh_job_tx(self, conn: sqlite3.Connection, job_id: str, now: float) -> None:
        job = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not job or job["status"] == "cancelled":
            return
        previous_status = job["status"]
        states = [r[0] for r in conn.execute("SELECT status FROM tasks WHERE job_id=?", (job_id,)).fetchall()]
        if states and all(s == "complete" for s in states):
            new = "complete"
        elif any(s == "failed" for s in states) and not any(s in {"pending", "leased", "running"} for s in states):
            new = "failed"
        elif states:
            new = "running"
        else:
            new = "queued"
        conn.execute("UPDATE jobs SET status=?,updated_at=? WHERE id=?", (new, now, job_id))
        if new in {"complete", "failed"} and new != previous_status:
            self._event(conn, "job_" + new, job_id=job_id)

    def list_jobs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("limit must be an integer between 1 and 500")
        with self._connection() as conn:
            rows = conn.execute("SELECT id,status,policy_digest,created_at,updated_at,cancelled_at FROM jobs ORDER BY created_at DESC,id LIMIT ?", (limit,)).fetchall()
            return [dict(row) for row in rows]

    def list_approvals(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("limit must be an integer between 1 and 500")
        with self._connection() as conn:
            rows = conn.execute("""SELECT id,job_id,target,tool_name,parameter_keys,policy_digest,status,
                requested_by,created_at,expires_at,decided_at,decided_by,revoked_at,revoked_by
                FROM approvals ORDER BY created_at DESC,id LIMIT ?""", (limit,)).fetchall()
            return [dict(row) for row in rows]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            return _decode(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            result = _decode(row)
            if result:
                result["dependencies"] = [r[0] for r in conn.execute("SELECT depends_on_task_id FROM task_dependencies WHERE task_id=? ORDER BY depends_on_task_id", (task_id,))]
            return result

    def list_tasks(self, job_id: str) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM tasks WHERE job_id=? ORDER BY created_at,id", (job_id,)).fetchall()
            return [_decode(r) for r in rows]

    def list_events(self, job_id: str, *, after_id: int = 0, limit: int = 1000) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM runtime_events WHERE job_id=? AND id>? ORDER BY id LIMIT ?", (job_id, after_id, limit)).fetchall()
            return [_decode(r) for r in rows]
