import json
import pathlib
import tempfile
import time
import unittest
import uuid

from appsec_agent.approval import ApprovalGateway
from appsec_agent.dispatcher import QueueDispatcher
from appsec_agent.policy import load_policy
from appsec_agent.runtime_store import RuntimeStore, policy_digest


class FakeSupervisor:
    def __init__(self):
        self.cancelled = []
        self.run_calls = []

    def cancel(self, execution_id):
        self.cancelled.append(execution_id)
        return True

    def run(self, payload, *, execution_id=None, network_required=False):
        self.run_calls.append((payload, execution_id, network_required))
        raise AssertionError("network task must not reach the worker without verified egress")


class QueueDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.store = RuntimeStore(self.root / "runtime.sqlite3")
        self.policy = load_policy(pathlib.Path(__file__).resolve().parents[1] / "policy.example.json")
        self.digest = policy_digest(self.policy)
        self.job = self.store.create_job(policy_digest=self.digest)
        self.target = "https://staging.example.test/api/health"
        self.params = {"method": "GET", "max_response_bytes": 1024}
        self.approvals = ApprovalGateway(self.store, self.policy)

    def add_approved_action(self):
        approval = self.approvals.request(job_id=self.job["id"], target=self.target,
            tool_name="http_request", parameters=self.params, policy_digest=self.digest,
            requested_by="requester", ttl_seconds=900)
        self.approvals.decide(approval["id"], approver_id="approver", approve=True)
        task = self.store.add_task(self.job["id"], "action-" + uuid.uuid4().hex, "tool_action",
            input={"target": self.target, "tool_name": "http_request", "parameters": self.params,
                   "approval_id": approval["id"], "action_id": "action-" + uuid.uuid4().hex})
        return task, approval

    def test_dispatch_claims_authorizes_then_fails_closed_before_network_worker(self):
        task, approval = self.add_approved_action()
        supervisor = FakeSupervisor()
        dispatcher = QueueDispatcher(self.store, self.policy, supervisor=supervisor)
        result = dispatcher.dispatch_once("dispatcher-test", job_id=self.job["id"])
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["reason"], "isolated_backend_unavailable")
        self.assertEqual(self.store.get_task(task["id"])["status"], "blocked")
        self.assertEqual(self.approvals.get(approval["id"])["status"], "consumed")
        self.assertEqual(supervisor.run_calls, [])
        self.assertTrue(self.store.verify_audit_chain()["valid"])

    def test_dispatch_claims_only_tool_action_tasks(self):
        self.store.add_task(self.job["id"], "ordinary", "report", input={"report": "summary"})
        result = QueueDispatcher(self.store, self.policy).dispatch_once("dispatcher-test", job_id=self.job["id"])
        self.assertEqual(result["state"], "idle")
        tasks = self.store.list_tasks(self.job["id"])
        self.assertEqual(tasks[0]["status"], "pending")

    def test_malformed_action_is_failed_without_worker_invocation(self):
        task = self.store.add_task(self.job["id"], "malformed", "tool_action", input={"tool_name": "dynamic"})
        supervisor = FakeSupervisor()
        result = QueueDispatcher(self.store, self.policy, supervisor=supervisor).dispatch_once(
            "dispatcher-test", job_id=self.job["id"])
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["reason"], "authorization_denied")
        self.assertEqual(self.store.get_task(task["id"])["status"], "failed")
        self.assertEqual(supervisor.run_calls, [])

    def test_supervisor_cancellation_is_registered_with_runtime_store(self):
        supervisor = FakeSupervisor()
        QueueDispatcher(self.store, self.policy, supervisor=supervisor)
        self.assertIn(supervisor.cancel, self.store._execution_cancellers)

    def test_job_cancellation_invokes_registered_supervisor_for_running_execution(self):
        task, approval = self.add_approved_action()
        supervisor = FakeSupervisor()
        dispatcher = QueueDispatcher(self.store, self.policy, supervisor=supervisor)
        claimed = self.store.claim_next("dispatcher-test", expected_policy_digest=self.digest,
                                        job_id=self.job["id"], task_type="tool_action")
        authorized = dispatcher.gateway.authorize_task(task["id"], claimed["lease_token"])
        execution_id = authorized["execution_id"]
        with self.store._transaction() as conn:
            conn.execute("UPDATE execution_attempts SET state='running',started_at=?,updated_at=? WHERE id=?",
                         (time.time(), time.time(), execution_id))
            conn.execute("UPDATE tasks SET status='running',started_at=?,updated_at=? WHERE id=?",
                         (time.time(), time.time(), task["id"]))
        cancelled = self.store.cancel_job(self.job["id"], reason="integration test")
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(supervisor.cancelled, [execution_id])
        with self.store._connection() as conn:
            state = conn.execute("SELECT state FROM execution_attempts WHERE id=?", (execution_id,)).fetchone()["state"]
        self.assertEqual(state, "cancelled")

    def test_idle_dispatch_does_not_change_job(self):
        result = QueueDispatcher(self.store, self.policy).dispatch_once("dispatcher-test", job_id=self.job["id"])
        self.assertEqual(result, {"state": "idle", "reason": "no_claimable_tool_action"})
        self.assertEqual(self.store.get_job(self.job["id"])["status"], "queued")


if __name__ == "__main__":
    unittest.main()
