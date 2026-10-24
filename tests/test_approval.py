import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from appsec_agent.approval import ApprovalGateway, action_digest
from appsec_agent.runtime_store import InvalidTransition, RuntimeStore, RuntimeStoreError, policy_digest
from appsec_agent.policy import load_policy


class ApprovalGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = RuntimeStore(pathlib.Path(self.tmp.name) / "runtime.sqlite3")
        self.policy = load_policy(pathlib.Path(__file__).resolve().parents[1] / "policy.example.json")
        self.policy_hash = policy_digest(self.policy)
        self.job = self.store.create_job(policy_digest=self.policy_hash)
        self.gateway = ApprovalGateway(self.store, self.policy)
        self.action = {
            "job_id": self.job["id"],
            "target": "https://staging.example.test/api/health",
            "tool_name": "http_request",
            "parameters": {"method": "GET", "auth_profile": "staging-secret-profile", "max_response_bytes": 1200},
            "policy_digest": self.job["policy_digest"],
        }

    def request(self, **overrides):
        values = dict(self.action)
        values.update(overrides)
        return self.gateway.request(**values, requested_by="operator-a", ttl_seconds=900)

    def test_runtime_schema_v1_upgrades_to_v3_approval_and_execution_ledgers(self):
        legacy_path = pathlib.Path(self.tmp.name) / "legacy.sqlite3"
        with sqlite3.connect(legacy_path) as conn:
            conn.execute("CREATE TABLE runtime_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT INTO runtime_meta(key,value) VALUES('schema_version','1')")
        upgraded = RuntimeStore(legacy_path)
        with upgraded._connection() as conn:
            version = conn.execute("SELECT value FROM runtime_meta WHERE key='schema_version'").fetchone()[0]
            table = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='approvals'").fetchone()
        self.assertEqual(version, "3")
        self.assertIsNotNone(table)

    def test_digest_binds_target_tool_parameters_and_policy(self):
        original = action_digest(**self.action)
        for key, value in (("target", "https://other.example.test/api/health"),
                           ("tool_name", "different_tool"),
                           ("parameters", {"method": "POST"}),
                           ("policy_digest", "sha256:policy-v2")):
            changed = dict(self.action)
            changed[key] = value
            self.assertNotEqual(original, action_digest(**changed), key)

    def test_request_redacts_parameter_values_from_persistence(self):
        item = self.request()
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["parameter_keys"], ["auth_profile", "max_response_bytes", "method"])
        with self.store._connection() as conn:
            raw = str(dict(conn.execute("SELECT * FROM approvals WHERE id=?", (item["id"],)).fetchone()))
        self.assertNotIn("staging-secret-profile", raw)
        self.assertNotIn("1200", raw)

    def test_policy_digest_must_match_assessment(self):
        with self.assertRaises(RuntimeStoreError):
            self.request(policy_digest="sha256:stale-policy")

    def test_requester_cannot_approve_own_action(self):
        item = self.request()
        with self.assertRaises(InvalidTransition):
            self.gateway.decide(item["id"], approver_id="operator-a", approve=True)
        approved = self.gateway.decide(item["id"], approver_id="operator-b", approve=True, reason="Reviewed scope")
        self.assertEqual(approved["status"], "approved")

    def test_parameter_mutation_and_cross_job_reuse_fail_closed(self):
        item = self.request()
        self.gateway.decide(item["id"], approver_id="operator-b", approve=True)
        changed = dict(self.action)
        changed["parameters"] = {"method": "GET", "max_response_bytes": 1300}
        with self.assertRaises(RuntimeStoreError):
            self.gateway.consume(item["id"], **changed)
        changed = dict(self.action)
        changed["job_id"] = "job-another"
        with self.assertRaises(RuntimeStoreError):
            self.gateway.consume(item["id"], **changed)
        changed = dict(self.action)
        changed["target"] = "https://staging.example.test/api/other"
        with self.assertRaises(RuntimeStoreError):
            self.gateway.consume(item["id"], **changed)
        changed = dict(self.action)
        changed["policy_digest"] = "sha256:policy-v2"
        with self.assertRaises(RuntimeStoreError):
            self.gateway.consume(item["id"], **changed)
        self.assertEqual(self.gateway.get(item["id"])["status"], "approved")

    def test_approval_is_one_time_and_audited(self):
        item = self.request()
        self.gateway.decide(item["id"], approver_id="operator-b", approve=True)
        consumed = self.gateway.consume(item["id"], **self.action)
        self.assertEqual(consumed["status"], "consumed")
        with self.assertRaises(InvalidTransition):
            self.gateway.consume(item["id"], **self.action)
        event_types = [e["event_type"] for e in self.store.list_events(self.job["id"])]
        self.assertIn("approval_requested", event_types)
        self.assertIn("approval_approved", event_types)
        self.assertIn("approval_consumed", event_types)

    def test_expired_approval_cannot_be_approved_or_consumed(self):
        item = self.request()
        with self.store._transaction() as conn:
            conn.execute("UPDATE approvals SET expires_at=0 WHERE id=?", (item["id"],))
        expired = self.gateway.decide(item["id"], approver_id="operator-b", approve=True)
        self.assertEqual(expired["status"], "expired")
        with self.assertRaises(InvalidTransition):
            self.gateway.consume(item["id"], **self.action)

    def test_rejected_approval_cannot_be_consumed(self):
        item = self.request()
        rejected = self.gateway.decide(item["id"], approver_id="operator-b", approve=False, reason="Not in scope")
        self.assertEqual(rejected["status"], "rejected")
        with self.assertRaises(InvalidTransition):
            self.gateway.consume(item["id"], **self.action)

    def test_concurrent_consumers_cannot_replay_approval(self):
        item = self.request()
        self.gateway.decide(item["id"], approver_id="operator-b", approve=True)
        outcomes = []
        barrier = threading.Barrier(2)
        def consume():
            barrier.wait()
            try:
                outcomes.append(self.gateway.consume(item["id"], **self.action)["status"])
            except (InvalidTransition, RuntimeStoreError) as exc:
                outcomes.append(type(exc).__name__)
        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(outcomes.count("consumed"), 1)
        self.assertEqual(len(outcomes), 2)

    def test_invalid_action_inputs_rejected(self):
        with self.assertRaises(ValueError):
            action_digest(**{**self.action, "parameters": ["not", "an object"]})
        with self.assertRaises(ValueError):
            action_digest(**{**self.action, "parameters": {1: "numeric key"}})
        with self.assertRaises(ValueError):
            action_digest(**{**self.action, "parameters": {"number": float("nan")}})
        with self.assertRaises(ValueError):
            action_digest(**{**self.action, "target": "https://example.test/\nforged"})
        with self.assertRaises(ValueError):
            self.gateway.request(**self.action, requested_by="operator-a", ttl_seconds=1)

    def test_out_of_scope_target_is_rejected_before_approval(self):
        with self.assertRaises(RuntimeStoreError):
            self.request(target="https://attacker.example/api/health")

    def test_unknown_tools_and_unexpected_or_unsafe_parameters_are_rejected(self):
        with self.assertRaises(RuntimeStoreError):
            self.request(tool_name="shell_exec", parameters={"command": "id"})
        with self.assertRaises(RuntimeStoreError):
            self.request(parameters={"method": "GET", "headers": {"Host": "attacker.example"}})
        with self.assertRaises(RuntimeStoreError):
            self.request(parameters={"method": "POST"})
        with self.assertRaises(RuntimeStoreError):
            self.request(parameters={"method": "GET", "max_response_bytes": True})

    def test_cli_request_and_list_are_persistent_across_processes(self):
        repo = pathlib.Path(__file__).resolve().parents[1]
        db = str(pathlib.Path(self.tmp.name) / "cli-approval.sqlite3")
        def run_cli(*args, expect_success=True):
            completed = subprocess.run([sys.executable, str(repo / "artemis.py"), *args], cwd=repo,
                                       capture_output=True, text=True, timeout=10)
            if expect_success:
                self.assertEqual(completed.returncode, 0, completed.stderr)
                return json.loads(completed.stdout)
            self.assertNotEqual(completed.returncode, 0)
            return completed.stderr
        job = run_cli("--runtime-db", db, "--runtime-action", "create-job", "--policy", str(repo / "policy.example.json"))
        request = run_cli("--runtime-db", db, "--runtime-action", "approval-request", "--policy", str(repo / "policy.example.json"),
                          "--job-id", job["id"], "--action-target", "https://staging.example.test/api/health",
                          "--tool-name", "http_request", "--action-parameters", '{"method":"GET"}')
        listed = run_cli("--runtime-db", db, "--runtime-action", "approval-list", "--job-id", job["id"])
        self.assertEqual(request["status"], "pending")
        self.assertEqual([x["id"] for x in listed], [request["id"]])
        spoof_error = run_cli("--runtime-db", db, "--runtime-action", "approval-decide", "--approval-id", request["id"],
                              "--approval-decision", "approve", "--operator-id", "definitely-not-current-user", expect_success=False)
        self.assertIn("must match the current operating-system user", spoof_error)
        # USER/LOGNAME environment variables must not be able to impersonate another OS account.
        env = dict(os.environ, USER="environment-spoof", LOGNAME="environment-spoof")
        completed = subprocess.run([sys.executable, str(repo / "artemis.py"), "--runtime-db", db,
                                    "--runtime-action", "approval-decide", "--approval-id", request["id"],
                                    "--approval-decision", "approve", "--operator-id", "environment-spoof"],
                                   cwd=repo, capture_output=True, text=True, timeout=10, env=env)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("must match the current operating-system user", completed.stderr)


if __name__ == "__main__":
    unittest.main()
