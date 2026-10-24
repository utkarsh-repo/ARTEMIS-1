import json
import pathlib
import sqlite3
import tempfile
import time
import unittest
import uuid

from appsec_agent.approval import ApprovalGateway
from appsec_agent.authorization import AuthorizationDenied, AuthorizationGateway, InlineRequestAuthorizationGateway
from appsec_agent.policy import load_policy
from appsec_agent.runtime_store import InvalidTransition, RuntimeStore, RuntimeStoreError, policy_digest
from appsec_agent.tool_registry import tool_definition, validate_tool_action, ToolSchemaError


class AuthorizationGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.store = RuntimeStore(self.root / "runtime.sqlite3")
        self.policy = load_policy(pathlib.Path(__file__).resolve().parents[1] / "policy.example.json")
        self.digest = policy_digest(self.policy)
        self.job = self.store.create_job(policy_digest=self.digest)
        self.target = "https://staging.example.test/api/health"
        self.params = {"method": "GET", "max_response_bytes": 1200}
        self.approvals = ApprovalGateway(self.store, self.policy)

    def make_task(self, *, target=None, parameters=None, action_id=None):
        approval = self.approvals.request(job_id=self.job["id"], target=target or self.target,
            tool_name="http_request", parameters=parameters or self.params,
            policy_digest=self.digest, requested_by="requester", ttl_seconds=900)
        self.approvals.decide(approval["id"], approver_id="approver", approve=True)
        payload = {"target": target or self.target, "tool_name": "http_request",
            "parameters": parameters or self.params, "approval_id": approval["id"],
            "action_id": action_id or "action-" + uuid.uuid4().hex}
        task = self.store.add_task(self.job["id"], "tool-" + uuid.uuid4().hex, "tool_action", input=payload)
        claimed = self.store.claim_next("worker-test", expected_policy_digest=self.digest, job_id=self.job["id"])
        self.assertEqual(claimed["id"], task["id"])
        return task, claimed, approval, payload


    def test_legacy_inline_gateway_allows_only_in_scope_read_only_requests_and_redacts_query(self):
        events = []
        gateway = InlineRequestAuthorizationGateway(self.policy, assessment_id="legacy-test", audit=events.append)
        result = gateway.authorize_request(self.target + "?access_token=never-log-this", "GET")
        self.assertEqual(result["state"], "authorized")
        self.assertEqual(result["assessment_id"], "legacy-test")
        self.assertNotIn("never-log-this", json.dumps(events))
        with self.assertRaises(AuthorizationDenied):
            gateway.authorize_request("https://attacker.example/api/health", "GET")
        with self.assertRaises(AuthorizationDenied):
            gateway.authorize_request(self.target, "POST")
        for headers in (
            {"Host": "attacker.example"},
            {"Authorization": "Bearer secret"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"Transfer-Encoding": "chunked"},
            {"X-Test": "ok\r\nHost: attacker.example"},
        ):
            with self.assertRaises(AuthorizationDenied):
                gateway.authorize_request(self.target, "GET", headers=headers)
        with self.assertRaises(AuthorizationDenied):
            gateway.authorize_request(self.target, "GET", has_body=True)
        self.assertNotIn("Bearer secret", json.dumps(events))
        self.assertTrue(any(event["type"] == "authorization_denied" for event in events))

    def test_inline_action_digest_binds_auth_profile_and_header_values_without_logging_them(self):
        events = []
        gateway = InlineRequestAuthorizationGateway(self.policy, assessment_id="legacy-test", audit=events.append)
        one = gateway.authorize_request(self.target, "GET", headers={"X-Request-Mode": "one"}, auth_profile="anonymous")
        two = gateway.authorize_request(self.target, "GET", headers={"X-Request-Mode": "two"}, auth_profile="anonymous")
        three = gateway.authorize_request(self.target, "GET", headers={"X-Request-Mode": "one"}, auth_profile="default")
        self.assertNotEqual(one["action_digest"], two["action_digest"])
        self.assertNotEqual(one["action_digest"], three["action_digest"])
        self.assertRegex(one["headers_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("X-Request-Mode", json.dumps(events))
        self.assertNotIn('"one"', json.dumps(events))
        self.assertEqual(one["auth_profile"], "anonymous")

    def test_inline_gateway_rejects_ambiguous_auth_profile_identifiers(self):
        gateway = InlineRequestAuthorizationGateway(self.policy, assessment_id="legacy-test")
        for profile in ("LAB_TOKEN_bad-name", "LAB_COOKIE_", "default\nX", "other-profile"):
            with self.assertRaises(AuthorizationDenied):
                gateway.authorize_request(self.target, "GET", auth_profile=profile)

    def test_legacy_inline_gateway_denies_if_policy_snapshot_mutates(self):
        gateway = InlineRequestAuthorizationGateway(self.policy, assessment_id="legacy-test")
        self.policy["max_requests"] += 1
        with self.assertRaises(AuthorizationDenied):
            gateway.authorize_request(self.target, "GET")

    def test_tool_registry_publishes_fixed_version_and_execution_limits(self):
        definition = tool_definition("http_request")
        self.assertEqual(definition["version"], "1.0.0")
        self.assertEqual(definition["timeout_seconds"], 15)
        self.assertEqual(definition["max_response_bytes"], 250000)
        self.assertTrue(definition["approval_required"])
        with self.assertRaises(ToolSchemaError):
            validate_tool_action("dynamic_tool", {"method": "GET"})

    def test_authorizes_exact_approved_action_and_persists_execution_identity(self):
        task, claimed, approval, payload = self.make_task()
        result = AuthorizationGateway(self.store, self.policy).authorize_task(task["id"], claimed["lease_token"])
        self.assertEqual(result["state"], "authorized")
        self.assertEqual(result["approval_id"], approval["id"])
        self.assertEqual(result["tool_version"], "1.0.0")
        self.assertTrue(result["authorization_digest"].startswith("sha256:"))
        self.assertEqual(self.approvals.get(approval["id"])["status"], "consumed")
        with self.store._connection() as conn:
            row = conn.execute("SELECT * FROM execution_attempts WHERE id=?", (result["execution_id"],)).fetchone()
        self.assertEqual(row["state"], "authorized")
        self.assertEqual(row["action_id"], payload["action_id"])
        self.assertTrue(self.store.verify_audit_chain()["valid"])

    def test_direct_runtime_start_and_completion_cannot_bypass_gateway(self):
        task, claimed, approval, _ = self.make_task()
        with self.assertRaises(InvalidTransition):
            self.store.start_task(task["id"], claimed["lease_token"])
        with self.assertRaises(InvalidTransition):
            self.store.complete_task(task["id"], claimed["lease_token"], result={"evidence_id": "fake"})
        self.assertEqual(self.store.get_task(task["id"])["status"], "leased")
        self.assertEqual(self.approvals.get(approval["id"])["status"], "approved")

    def test_parameter_substitution_after_approval_is_denied(self):
        task, claimed, approval, _ = self.make_task()
        altered = {"target": self.target, "tool_name": "http_request", "parameters": {"method": "HEAD"},
                   "approval_id": approval["id"], "action_id": "action-substitution"}
        with self.store._transaction() as conn:
            conn.execute("UPDATE tasks SET input=? WHERE id=?", (json.dumps(altered), task["id"]))
        with self.assertRaises(AuthorizationDenied):
            AuthorizationGateway(self.store, self.policy).authorize_task(task["id"], claimed["lease_token"])
        self.assertEqual(self.approvals.get(approval["id"])["status"], "approved")

    def test_policy_change_denies_claimed_task(self):
        task, claimed, approval, _ = self.make_task()
        changed = dict(self.policy)
        changed["max_requests"] = changed["max_requests"] + 1
        with self.assertRaises(AuthorizationDenied):
            AuthorizationGateway(self.store, changed).authorize_task(task["id"], claimed["lease_token"])
        self.assertEqual(self.approvals.get(approval["id"])["status"], "approved")

    def test_expired_approval_is_denied(self):
        task, claimed, approval, _ = self.make_task()
        with self.store._transaction() as conn:
            conn.execute("UPDATE approvals SET expires_at=? WHERE id=?", (time.time() - 1, approval["id"]))
        with self.assertRaises(AuthorizationDenied):
            AuthorizationGateway(self.store, self.policy).authorize_task(task["id"], claimed["lease_token"])
        self.assertEqual(self.approvals.get(approval["id"])["status"], "expired")


    def test_approval_expiry_after_authorization_blocks_start(self):
        task, claimed, approval, _ = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        with self.store._transaction() as conn:
            conn.execute("UPDATE approvals SET expires_at=? WHERE id=?", (time.time() - 1, approval["id"]))
        result = gateway.begin_execution(auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"])
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["reason"], "approval_stale_or_revoked")

    def test_approval_expiry_before_result_commit_is_rejected(self):
        task, claimed, approval, payload = self.make_task()
        evidence_dir = self.root / "evidence-expiry"
        evidence_dir.mkdir()
        (evidence_dir / "evidence.jsonl").write_text(json.dumps({"evidence_id": "ev-expiry", "request": {"url": self.target, "method": "GET", "action_id": payload["action_id"]}, "response": {"status": 200}}) + "\n")
        gateway = AuthorizationGateway(self.store, self.policy, evidence_dir=evidence_dir)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        with self.store._transaction() as conn:
            conn.execute("UPDATE execution_attempts SET state='running',started_at=?,updated_at=? WHERE id=?", (time.time(), time.time(), auth["execution_id"]))
            conn.execute("UPDATE tasks SET status='running',started_at=?,updated_at=? WHERE id=?", (time.time(), time.time(), task["id"]))
            conn.execute("UPDATE approvals SET expires_at=? WHERE id=?", (time.time() - 1, approval["id"]))
        with self.assertRaises(AuthorizationDenied):
            gateway.complete_execution(auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"], result={"evidence_id": "ev-expiry"})
        self.assertEqual(self.store.get_task(task["id"])["status"], "running")

    def test_revoked_approval_is_denied_before_authorization(self):
        task, claimed, approval, _ = self.make_task()
        self.approvals.revoke(approval["id"], revoked_by="security-reviewer", reason="scope changed")
        with self.assertRaises(AuthorizationDenied):
            AuthorizationGateway(self.store, self.policy).authorize_task(task["id"], claimed["lease_token"])

    def test_replay_of_action_id_is_denied(self):
        action_id = "action-replay-test"
        task1, claim1, _, _ = self.make_task(action_id=action_id)
        AuthorizationGateway(self.store, self.policy).authorize_task(task1["id"], claim1["lease_token"])
        task2, claim2, _, _ = self.make_task(action_id=action_id)
        with self.assertRaises(AuthorizationDenied):
            AuthorizationGateway(self.store, self.policy).authorize_task(task2["id"], claim2["lease_token"])

    def test_stale_lease_cannot_authorize(self):
        task, claimed, approval, _ = self.make_task()
        self.store.cancel_job(self.job["id"])
        with self.assertRaises(AuthorizationDenied):
            AuthorizationGateway(self.store, self.policy).authorize_task(task["id"], claimed["lease_token"])

    def test_registered_tool_and_target_scope_are_revalidated(self):
        task, claimed, approval, payload = self.make_task()
        payload["target"] = "https://attacker.example/api/health"
        with self.store._transaction() as conn:
            conn.execute("UPDATE tasks SET input=? WHERE id=?", (json.dumps(payload), task["id"]))
        with self.assertRaises(AuthorizationDenied):
            AuthorizationGateway(self.store, self.policy).authorize_task(task["id"], claimed["lease_token"])

    def test_start_rechecks_approval_revocation_and_policy(self):
        task, claimed, approval, _ = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        self.approvals.revoke(approval["id"], revoked_by="security-reviewer", reason="revoked after authorization")
        started = gateway.begin_execution(auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"])
        self.assertEqual(started["state"], "blocked")
        self.assertEqual(self.store.get_task(task["id"])["status"], "blocked")

    def test_valid_action_stays_blocked_without_isolated_backend(self):
        task, claimed, approval, _ = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        result = gateway.begin_execution(auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"])
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["reason"], "isolated_backend_unavailable")
        self.assertEqual(self.store.get_task(task["id"])["status"], "blocked")
        with self.store._connection() as conn:
            state = conn.execute("SELECT state FROM execution_attempts WHERE id=?", (auth["execution_id"],)).fetchone()[0]
        self.assertEqual(state, "blocked")

    def test_successful_execution_requires_durable_evidence_and_commits_atomically(self):
        task, claimed, approval, payload = self.make_task()
        evidence_dir = self.root / "evidence"
        evidence_dir.mkdir()
        (evidence_dir / "evidence.jsonl").write_text(json.dumps({"evidence_id": "ev-fixture-1", "request": {"url": self.target, "method": "GET", "action_id": payload["action_id"]}, "response": {"status": 200}}) + "\n")
        gateway = AuthorizationGateway(self.store, self.policy, evidence_dir=evidence_dir)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        # No real supervisor exists in this build. Seed the running state to test
        # the atomic completion contract independently of production dispatch.
        with self.store._transaction() as conn:
            conn.execute("UPDATE execution_attempts SET state='running',started_at=?,updated_at=? WHERE id=?", (time.time(), time.time(), auth["execution_id"]))
            conn.execute("UPDATE tasks SET status='running',started_at=?,updated_at=? WHERE id=?", (time.time(), time.time(), task["id"]))
        completed = gateway.complete_execution(auth["execution_id"], task_id=task["id"],
            lease_token=claimed["lease_token"], result={"evidence_id": "ev-fixture-1", "status": 200})
        self.assertEqual(completed["state"], "completed")
        self.assertEqual(self.store.get_task(task["id"])["status"], "complete")
        with self.store._connection() as conn:
            state = conn.execute("SELECT state FROM execution_attempts WHERE id=?", (auth["execution_id"],)).fetchone()[0]
        self.assertEqual(state, "completed")
        self.assertTrue(self.store.verify_audit_chain()["valid"])

    def test_crash_recovery_marks_authorized_execution_recovery_required(self):
        task, claimed, approval, _ = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        with self.store._transaction() as conn:
            conn.execute("UPDATE tasks SET lease_expires_at=0 WHERE id=?", (task["id"],))
        recovered = self.store.recover_expired()
        self.assertEqual(recovered["failed"], 1)
        self.assertEqual(self.store.get_task(task["id"])["status"], "failed")
        with self.store._connection() as conn:
            state = conn.execute("SELECT state FROM execution_attempts WHERE id=?", (auth["execution_id"],)).fetchone()[0]
        self.assertEqual(state, "recovery_required")

    def test_action_mutation_after_authorization_blocks_start(self):
        task, claimed, approval, payload = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        payload["parameters"] = {"method": "HEAD"}
        with self.store._transaction() as conn:
            conn.execute("UPDATE tasks SET input=? WHERE id=?", (json.dumps(payload), task["id"]))
        started = gateway.begin_execution(auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"])
        self.assertEqual(started["state"], "blocked")
        self.assertEqual(self.store.get_task(task["id"])["status"], "blocked")

    def test_policy_change_after_authorization_blocks_start(self):
        task, claimed, approval, _ = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        changed = dict(self.policy)
        changed["max_requests"] += 1
        started = AuthorizationGateway(self.store, changed).begin_execution(
            auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"])
        self.assertEqual(started["state"], "blocked")
        self.assertEqual(self.store.get_task(task["id"])["status"], "blocked")

    def test_missing_evidence_cannot_complete_execution(self):
        task, claimed, approval, _ = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy, evidence_dir=self.root / "missing-evidence")
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        with self.store._transaction() as conn:
            conn.execute("UPDATE execution_attempts SET state='running' WHERE id=?", (auth["execution_id"],))
            conn.execute("UPDATE tasks SET status='running' WHERE id=?", (task["id"],))
        with self.assertRaises(AuthorizationDenied):
            gateway.complete_execution(auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"],
                                       result={"evidence_id": "ev-does-not-exist"})
        self.assertEqual(self.store.get_task(task["id"])["status"], "running")

    def test_evidence_for_another_target_cannot_complete_action(self):
        task, claimed, approval, _ = self.make_task()
        evidence_dir = self.root / "evidence-mismatch"
        evidence_dir.mkdir()
        (evidence_dir / "evidence.jsonl").write_text(json.dumps({"evidence_id": "ev-other-target", "request": {"url": "https://other.example/", "method": "GET"}, "response": {"status": 200}}) + "\n")
        gateway = AuthorizationGateway(self.store, self.policy, evidence_dir=evidence_dir)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        with self.store._transaction() as conn:
            conn.execute("UPDATE execution_attempts SET state='running' WHERE id=?", (auth["execution_id"],))
            conn.execute("UPDATE tasks SET status='running' WHERE id=?", (task["id"],))
        with self.assertRaises(AuthorizationDenied):
            gateway.complete_execution(auth["execution_id"], task_id=task["id"], lease_token=claimed["lease_token"], result={"evidence_id": "ev-other-target"})
        self.assertEqual(self.store.get_task(task["id"])["status"], "running")

    def test_audit_chain_detects_row_tampering_and_redacts_url_secrets(self):
        self.store._event_in_new_transaction("fixture", job_id=self.job["id"], payload={
            "target": "https://staging.example.test/api?access_token=supersecret", "note": "Bearer abcdefghijklmnop"})
        self.assertTrue(self.store.verify_audit_chain()["valid"])
        events = self.store.list_events(self.job["id"])
        fixture = next(e for e in events if e["event_type"] == "fixture")
        self.assertNotIn("supersecret", json.dumps(fixture))
        with self.store._transaction() as conn:
            conn.execute("UPDATE runtime_events SET payload='{}' WHERE event_type='fixture'")
        self.assertFalse(self.store.verify_audit_chain()["valid"])

    def test_audit_hash_nullification_is_not_reanchored_on_reopen(self):
        self.store._event_in_new_transaction("fixture", job_id=self.job["id"], payload={"status": "ok"})
        with self.store._transaction() as conn:
            conn.execute("UPDATE runtime_events SET event_hash=NULL WHERE id=(SELECT MAX(id) FROM runtime_events)")
        reopened = RuntimeStore(self.root / "runtime.sqlite3")
        self.assertFalse(reopened.verify_audit_chain()["valid"])

    def test_audit_head_detects_tail_deletion_after_reopen(self):
        self.store._event_in_new_transaction("fixture", job_id=self.job["id"], payload={"status": "ok"})
        self.assertTrue(self.store.verify_audit_chain()["valid"])
        with self.store._transaction() as conn:
            conn.execute("DELETE FROM runtime_events WHERE id=(SELECT MAX(id) FROM runtime_events)")
        reopened = RuntimeStore(self.root / "runtime.sqlite3")
        self.assertFalse(reopened.verify_audit_chain()["valid"])

    def test_cancel_invalidates_authorized_execution(self):
        task, claimed, approval, _ = self.make_task()
        gateway = AuthorizationGateway(self.store, self.policy)
        auth = gateway.authorize_task(task["id"], claimed["lease_token"])
        self.store.cancel_job(self.job["id"])
        with self.store._connection() as conn:
            state = conn.execute("SELECT state FROM execution_attempts WHERE id=?", (auth["execution_id"],)).fetchone()[0]
        self.assertEqual(state, "cancelled")
        self.assertEqual(self.store.get_task(task["id"])["status"], "cancelled")

    def test_runtime_schema_migrates_legacy_events_and_approvals(self):
        path = self.root / "legacy.sqlite3"
        with sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE runtime_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT INTO runtime_meta VALUES('schema_version','2')")
            conn.execute("CREATE TABLE runtime_events (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, task_id TEXT, event_type TEXT NOT NULL, at REAL NOT NULL, payload TEXT NOT NULL DEFAULT '{}')")
            conn.execute("INSERT INTO runtime_events(job_id,task_id,event_type,at,payload) VALUES(NULL,NULL,'legacy',1.0,'{}')")
        upgraded = RuntimeStore(path)
        self.assertTrue(upgraded.verify_audit_chain()["valid"])
        with upgraded._connection() as conn:
            version = conn.execute("SELECT value FROM runtime_meta WHERE key='schema_version'").fetchone()[0]
            cols = {r[1] for r in conn.execute("PRAGMA table_info(approvals)")}
        self.assertEqual(version, "3")
        self.assertIn("revoked_at", cols)


if __name__ == "__main__":
    unittest.main()
