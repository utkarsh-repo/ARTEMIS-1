import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest

from appsec_agent.runtime_store import (
    InvalidTransition, LeaseConflict, RuntimeStore, RuntimeStoreError, policy_digest,
)


class RuntimeStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = pathlib.Path(self.tmp.name) / "runtime.sqlite3"
        self.store = RuntimeStore(self.db)
        self.job = self.store.create_job(policy_digest="sha256:policy-test", idempotency_key="assessment-1")
        self.job_id = self.job["id"]

    def test_policy_digest_is_canonical_and_sensitive_to_policy_changes(self):
        one = {"base_url": "https://staging.example.test", "allowed_methods": ["GET"]}
        reordered = {"allowed_methods": ["GET"], "base_url": "https://staging.example.test"}
        changed = {"allowed_methods": ["GET", "HEAD"], "base_url": "https://staging.example.test"}
        self.assertEqual(policy_digest(one), policy_digest(reordered))
        self.assertNotEqual(policy_digest(one), policy_digest(changed))
        self.assertTrue(policy_digest(one).startswith("sha256:"))

    def test_idempotent_job_creation_is_bound_to_policy_digest(self):
        same = self.store.create_job(policy_digest="sha256:policy-test", idempotency_key="assessment-1")
        self.assertEqual(same["id"], self.job_id)
        with self.assertRaises(RuntimeStoreError):
            self.store.create_job(policy_digest="sha256:other-policy", idempotency_key="assessment-1")

    def test_worker_must_present_exact_job_policy_digest(self):
        self.store.add_task(self.job_id, "guarded", "check")
        with self.assertRaises(RuntimeStoreError):
            self.store.claim_next("worker", expected_policy_digest="sha256:wrong", job_id=self.job_id)
        claimed = self.store.claim_next("worker", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        self.assertIsNotNone(claimed)

    def test_dependencies_gate_claims_until_prerequisite_completes(self):
        first = self.store.add_task(self.job_id, "inventory", "inventory")
        second = self.store.add_task(self.job_id, "headers", "security_headers", dependencies=[first["id"]])
        claimed = self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        self.assertEqual(claimed["id"], first["id"])
        self.assertNotEqual(claimed["id"], second["id"])
        self.store.complete_task(first["id"], claimed["lease_token"], result={"observed": True})
        claimed_second = self.store.claim_next("worker-b", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        self.assertEqual(claimed_second["id"], second["id"])
        self.store.complete_task(second["id"], claimed_second["lease_token"], result={"checks": 3})
        self.assertEqual(self.store.get_job(self.job_id)["status"], "complete")

    def test_dependency_cycle_rejected_atomically(self):
        a = self.store.add_task(self.job_id, "a", "check-a")
        b = self.store.add_task(self.job_id, "b", "check-b", dependencies=[a["id"]])
        with self.assertRaises(ValueError):
            self.store.add_task(self.job_id, "a", "check-a", dependencies=[b["id"]])
        self.assertEqual(self.store.get_task(a["id"])["dependencies"], [])

    def test_failed_prerequisite_blocks_descendant_instead_of_hanging(self):
        parent = self.store.add_task(self.job_id, "parent", "check", max_attempts=1)
        child = self.store.add_task(self.job_id, "child", "dependent", dependencies=[parent["id"]])
        claimed = self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        self.store.fail_task(parent["id"], claimed["lease_token"], "terminal", retryable=False)
        self.assertIsNone(self.store.claim_next("worker-b", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id))
        self.assertEqual(self.store.get_task(child["id"])["status"], "blocked")
        self.assertEqual(self.store.get_job(self.job_id)["status"], "failed")

    def test_lease_token_required_for_all_mutations(self):
        task = self.store.add_task(self.job_id, "one", "check")
        claimed = self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        with self.assertRaises(LeaseConflict):
            self.store.complete_task(task["id"], "wrong-token", result={})
        self.store.start_task(task["id"], claimed["lease_token"])
        self.store.heartbeat(task["id"], claimed["lease_token"], lease_seconds=30)
        self.store.complete_task(task["id"], claimed["lease_token"], result={"ok": True})
        with self.assertRaises(LeaseConflict):
            self.store.heartbeat(task["id"], claimed["lease_token"])

    def test_retryable_failure_returns_task_to_queue_then_fails_closed_at_limit(self):
        task = self.store.add_task(self.job_id, "retry", "check", max_attempts=2)
        first = self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        pending = self.store.fail_task(task["id"], first["lease_token"], "temporary error")
        self.assertEqual(pending["status"], "pending")
        second = self.store.claim_next("worker-b", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        failed = self.store.fail_task(task["id"], second["lease_token"], "persistent error")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(self.store.get_job(self.job_id)["status"], "failed")

    def test_expired_lease_recovery_is_audited_and_retry_bounded(self):
        task = self.store.add_task(self.job_id, "lease", "check", max_attempts=2)
        claimed = self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], lease_seconds=5, job_id=self.job_id)
        with self.store._connect() as conn:
            conn.execute("UPDATE tasks SET lease_expires_at=0 WHERE id=?", (task["id"],))
        recovered = self.store.recover_expired()
        self.assertEqual(recovered["retried"], 1)
        self.assertEqual(self.store.get_task(task["id"])["status"], "pending")
        again = self.store.claim_next("worker-b", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        with self.store._connect() as conn:
            conn.execute("UPDATE tasks SET lease_expires_at=0 WHERE id=?", (task["id"],))
        recovered = self.store.recover_expired()
        self.assertEqual(recovered["failed"], 1)
        self.assertEqual(self.store.get_task(task["id"])["status"], "failed")
        events = self.store.list_events(self.job_id)
        self.assertTrue(any(e["event_type"] == "task_lease_expired_failed" for e in events))

    def test_claim_path_refreshes_job_after_last_lease_expires(self):
        task = self.store.add_task(self.job_id, "last", "check", max_attempts=1)
        self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], lease_seconds=5, job_id=self.job_id)
        with self.store._connection() as conn:
            conn.execute("UPDATE tasks SET lease_expires_at=0 WHERE id=?", (task["id"],))
        self.assertIsNone(self.store.claim_next("worker-b", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id))
        self.assertEqual(self.store.get_task(task["id"])["status"], "failed")
        self.assertEqual(self.store.get_job(self.job_id)["status"], "failed")

    def test_cancellation_invalidates_worker_lease_and_pending_work(self):
        task = self.store.add_task(self.job_id, "one", "check")
        claimed = self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        self.store.cancel_job(self.job_id, reason="operator stop")
        self.assertEqual(self.store.get_task(task["id"])["status"], "cancelled")
        with self.assertRaises(InvalidTransition):
            self.store.complete_task(task["id"], claimed["lease_token"], result={})
        self.assertEqual(self.store.get_job(self.job_id)["status"], "cancelled")


    def test_running_execution_cancellation_requires_confirmed_supervisor_termination(self):
        task = self.store.add_task(self.job_id, "active", "tool_action")
        claimed = self.store.claim_next("worker-a", expected_policy_digest=self.job["policy_digest"], job_id=self.job_id)
        # Seed a running execution as an integration fixture; the real gateway
        # remains fail-closed until a supported isolated backend is configured.
        with self.store._transaction() as conn:
            conn.execute("UPDATE tasks SET status='running' WHERE id=?", (task["id"],))
            conn.execute("INSERT INTO approvals(id,job_id,action_digest,target,tool_name,parameter_keys,policy_digest,status,requested_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("approval-cancel", self.job_id, "sha256:action", "https://staging.example.test", "http_request", '["method"]', self.job["policy_digest"], "consumed", "requester", 1.0, 9999999999.0))
            conn.execute("INSERT INTO execution_attempts(id,action_id,job_id,task_id,worker_id,approval_id,authorization_digest,policy_digest,tool_name,tool_version,state,created_at,updated_at,started_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("exec-cancel", "action-cancel", self.job_id, task["id"], "worker-a", "approval-cancel", "sha256:auth", self.job["policy_digest"], "http_request", "1.0.0", "running", 1.0, 1.0, 1.0))
        with self.assertRaises(InvalidTransition, msg="missing supervisor must not acknowledge cancellation"):
            self.store.cancel_job(self.job_id)
        self.assertNotEqual(self.store.get_job(self.job_id)["status"], "cancelled")
        cancelled = []
        self.store.register_execution_canceller(lambda execution_id: cancelled.append(execution_id) or execution_id == "exec-cancel")
        self.store.cancel_job(self.job_id, reason="test stop")
        self.assertEqual(cancelled, ["exec-cancel"])
        self.assertEqual(self.store.get_job(self.job_id)["status"], "cancelled")
        with self.store._connection() as conn:
            state = conn.execute("SELECT state FROM execution_attempts WHERE id='exec-cancel'").fetchone()[0]
        self.assertEqual(state, "cancelled")

    def test_running_execution_cancellation_rolls_back_when_supervisor_cannot_confirm(self):
        task = self.store.add_task(self.job_id, "active-unconfirmed", "tool_action")
        with self.store._transaction() as conn:
            conn.execute("UPDATE tasks SET status='running' WHERE id=?", (task["id"],))
            conn.execute("INSERT INTO approvals(id,job_id,action_digest,target,tool_name,parameter_keys,policy_digest,status,requested_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("approval-cancel-2", self.job_id, "sha256:action", "https://staging.example.test", "http_request", '["method"]', self.job["policy_digest"], "consumed", "requester", 1.0, 9999999999.0))
            conn.execute("INSERT INTO execution_attempts(id,action_id,job_id,task_id,worker_id,approval_id,authorization_digest,policy_digest,tool_name,tool_version,state,created_at,updated_at,started_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("exec-unconfirmed", "action-unconfirmed", self.job_id, task["id"], "worker-a", "approval-cancel-2", "sha256:auth", self.job["policy_digest"], "http_request", "1.0.0", "running", 1.0, 1.0, 1.0))
        self.store.register_execution_canceller(lambda _execution_id: False)
        with self.assertRaises(InvalidTransition):
            self.store.cancel_job(self.job_id)
        self.assertNotEqual(self.store.get_job(self.job_id)["status"], "cancelled")
        self.assertEqual(self.store.get_task(task["id"])["status"], "running")
        self.assertTrue(any(event["event_type"] == "job_cancellation_unconfirmed" for event in self.store.list_events(self.job_id)))

    def test_competing_workers_cannot_claim_same_task(self):
        task = self.store.add_task(self.job_id, "single", "check")
        barrier = threading.Barrier(3)
        claims = []
        failures = []
        def worker(name):
            try:
                barrier.wait()
                claims.append(self.store.claim_next(name, expected_policy_digest=self.job["policy_digest"], job_id=self.job_id))
            except Exception as exc:  # surfaced in the assertion below
                failures.append(exc)
        threads = [threading.Thread(target=worker, args=(f"worker-{i}",)) for i in range(2)]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join(timeout=5)
        self.assertFalse(failures, failures)
        self.assertEqual(sum(claim is not None for claim in claims), 1)
        self.assertEqual(self.store.get_task(task["id"])["status"], "leased")

    def test_input_validation_and_database_permissions(self):
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            self.store.add_task(self.job_id, "bad", "check", max_attempts=0)
        with self.assertRaises(ValueError):
            self.store.claim_next("worker", expected_policy_digest=self.job["policy_digest"], lease_seconds=1)

    def test_runtime_metadata_and_results_redact_common_secrets(self):
        private_job = self.store.create_job(policy_digest="sha256:private", metadata={"api_key": "do-not-store"})
        self.assertNotIn("do-not-store", json.dumps(private_job))
        task = self.store.add_task(private_job["id"], "safe", "check", input={"token": "input-secret", "name": "ok"})
        self.assertNotIn("input-secret", json.dumps(task))
        claimed = self.store.claim_next("worker", expected_policy_digest=private_job["policy_digest"], job_id=private_job["id"])
        done = self.store.complete_task(task["id"], claimed["lease_token"], result={"access_token": "result-secret", "status": "ok"})
        self.assertNotIn("result-secret", json.dumps(done))
        self.assertEqual(done["result"]["status"], "ok")

    def test_runtime_database_symlink_is_rejected(self):
        real = pathlib.Path(self.tmp.name) / "real.sqlite3"
        RuntimeStore(real)
        alias = pathlib.Path(self.tmp.name) / "alias.sqlite3"
        alias.symlink_to(real)
        with self.assertRaises(ValueError):
            RuntimeStore(alias)

    def test_runtime_cli_rejects_policy_digest_override_mismatch(self):
        repo = pathlib.Path(__file__).resolve().parents[1]
        db = str(pathlib.Path(self.tmp.name) / "mismatch.sqlite3")
        completed = subprocess.run([sys.executable, str(repo / "artemis.py"), "--runtime-db", db,
                                    "--runtime-action", "create-job", "--policy", str(repo / "policy.example.json"),
                                    "--policy-digest", "sha256:forged"], cwd=repo, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not match", completed.stderr)

    def test_runtime_cli_create_add_and_status_across_processes(self):
        repo = pathlib.Path(__file__).resolve().parents[1]
        def run_cli(*args):
            completed = subprocess.run([sys.executable, str(repo / "artemis.py"), *args], cwd=repo,
                                       capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return json.loads(completed.stdout)
        db = str(pathlib.Path(self.tmp.name) / "cli.sqlite3")
        job = run_cli("--runtime-db", db, "--runtime-action", "create-job", "--policy", str(repo / "policy.example.json"), "--idempotency-key", "cli-smoke")
        task = run_cli("--runtime-db", db, "--runtime-action", "add-task", "--job-id", job["id"], "--task-key", "baseline", "--task-type", "baseline")
        claimed = run_cli("--runtime-db", db, "--runtime-action", "claim", "--policy", str(repo / "policy.example.json"),
                          "--job-id", job["id"], "--worker-id", "cli-worker")
        status = run_cli("--runtime-db", db, "--runtime-action", "status", "--job-id", job["id"])
        self.assertEqual(status["job"]["id"], job["id"])
        self.assertEqual(status["tasks"][0]["id"], task["id"])
        self.assertEqual(status["tasks"][0]["status"], "leased")
        self.assertEqual(status["tasks"][0]["lease_token"], claimed["lease_token"])

    def test_events_are_ordered_and_payloads_decoded(self):
        self.store.add_task(self.job_id, "one", "check")
        events = self.store.list_events(self.job_id)
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual([e["id"] for e in events], sorted(e["id"] for e in events))
        self.assertTrue(all(isinstance(e["payload"], dict) for e in events))


if __name__ == "__main__":
    unittest.main()
