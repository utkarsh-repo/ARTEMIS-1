import json
import pathlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from appsec_agent.operator_api import OperatorControlServer
from appsec_agent.runtime_store import RuntimeStore


class OperatorAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = pathlib.Path(self.tmp.name) / "runtime.sqlite3"
        self.store = RuntimeStore(self.db)
        self.job = self.store.create_job(policy_digest="sha256:fixture")
        credentials = {
            "v" * 32: {"operator_id": "viewer-1", "role": "viewer"},
            "o" * 32: {"operator_id": "operator-1", "role": "operator"},
            "a" * 32: {"operator_id": "approver-1", "role": "approver"},
            "x" * 32: {"operator_id": "admin-1", "role": "admin"},
        }
        self.tokens = {record["role"]: token for token, record in credentials.items()}
        self.server = OperatorControlServer(("127.0.0.1", 0), runtime_db=self.db, credentials=credentials)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=3)

    def request(self, path, *, role=None, method="GET", body=None):
        headers = {}
        if role: headers["Authorization"] = "Bearer " + self.tokens[role]
        data = None
        if body is not None:
            data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_authentication_required_and_invalid_token_rejected(self):
        self.assertEqual(self.request("/health")[0], 401)
        req = urllib.request.Request(self.base + "/health", headers={"Authorization": "Bearer " + "z" * 32})
        with self.assertRaises(urllib.error.HTTPError) as caught: urllib.request.urlopen(req, timeout=3)
        self.assertEqual(caught.exception.code, 401)

    def test_viewer_can_read_but_cannot_cancel_even_with_spoofed_role(self):
        status, health = self.request("/health", role="viewer")
        self.assertEqual(status, 200); self.assertTrue(health["ok"])
        status, body = self.request(f"/jobs/{self.job['id']}/cancel", role="viewer", method="POST",
                                    body={"role": "admin", "reason": "spoof"})
        self.assertEqual(status, 403)
        self.assertNotEqual(self.store.get_job(self.job["id"])["status"], "cancelled")

    def test_operator_can_cancel_and_identity_is_server_side(self):
        status, result = self.request(f"/jobs/{self.job['id']}/cancel", role="operator", method="POST",
                                      body={"operator_id": "admin", "role": "admin", "reason": "test"})
        self.assertEqual(status, 200)
        self.assertEqual(result["operator_id"], "operator-1")
        self.assertEqual(self.store.get_job(self.job["id"])["status"], "cancelled")


    def test_approval_decision_and_revocation_require_separate_server_roles(self):
        from appsec_agent.approval import ApprovalGateway
        from appsec_agent.policy import load_policy
        from appsec_agent.runtime_store import policy_digest
        policy = load_policy(pathlib.Path(__file__).resolve().parents[1] / "policy.example.json")
        digest = policy_digest(policy)
        job = self.store.create_job(policy_digest=digest)
        self.server.policy = policy
        gateway = ApprovalGateway(self.store, policy)
        approval = gateway.request(job_id=job["id"], target=policy["base_url"] + "/health",
                                   tool_name="http_request", parameters={"method": "GET"},
                                   policy_digest=digest, requested_by="requester")
        status, _ = self.request(f"/approvals/{approval['id']}/decision", role="operator", method="POST",
                                 body={"approve": True, "role": "admin"})
        self.assertEqual(status, 403)
        status, decided = self.request(f"/approvals/{approval['id']}/decision", role="approver", method="POST",
                                       body={"approve": True, "operator_id": "forged"})
        self.assertEqual(status, 200)
        self.assertEqual(decided["decided_by"], "approver-1")
        status, _ = self.request(f"/approvals/{approval['id']}/revoke", role="operator", method="POST", body={})
        self.assertEqual(status, 403)
        status, revoked = self.request(f"/approvals/{approval['id']}/revoke", role="admin", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertIsNotNone(revoked["revoked_at"])


    def test_dashboard_is_same_origin_and_api_exposes_only_sanitized_persisted_state(self):
        req = urllib.request.Request(self.base + "/")
        with urllib.request.urlopen(req, timeout=3) as response:
            html = response.read().decode()
            self.assertEqual(response.status, 200)
            self.assertIn("ARTEMIS Operations", html)
            self.assertIn("assessmentdetails", html)
            self.assertIn("approvalAction", html)
            self.assertIn("Content-Security-Policy", response.headers)
            self.assertNotIn("https://cdn", html)
        task = self.store.add_task(self.job["id"], "sensitive-task", "report",
                                   input={"target": "https://staging.example.test/?token=secret-value"})
        status, jobs = self.request("/jobs", role="viewer")
        self.assertEqual(status, 200)
        self.assertEqual(jobs["jobs"][0]["id"], self.job["id"])
        status, details = self.request(f"/jobs/{self.job['id']}", role="viewer")
        self.assertEqual(status, 200)
        self.assertIn("tasks", details)
        self.assertNotIn("input", details["tasks"][0])
        self.assertNotIn("result", details["tasks"][0])
        self.assertNotIn("secret-value", json.dumps(details))


    def test_dashboard_assessment_and_approval_views_are_persisted_and_redacted(self):
        run_root = pathlib.Path(self.tmp.name) / "runs"
        assessment = run_root / "assessment-1"
        assessment.mkdir(parents=True)
        (assessment / "run_summary.json").write_text(json.dumps({
            "target": "https://staging.example.test/?token=should-not-leak", "provider": "offline",
            "requests_used": 1, "findings_count": 1, "finished_at": 123.0}))
        (assessment / "blackboard.json").write_text(json.dumps({
            "assets": [{"value": "https://staging.example.test/?api_key=should-not-leak"}],
            "claims": [{"title": "Candidate", "status": "pending_verification"}],
            "test_statuses": {"security_headers": {"status": "executed"}}}))
        (assessment / "findings.jsonl").write_text(json.dumps({
            "finding_id": "fn-1", "title": "Missing header", "url": "https://staging.example.test/?token=should-not-leak",
            "details": {"client_secret": "should-not-leak"}, "traffic_ids": [], "severity": "low"}) + "\n")
        (assessment / "events.jsonl").write_text(json.dumps({"type": "fixture", "url": "https://staging.example.test/?token=should-not-leak"}) + "\n")
        self.server.run_root = run_root.resolve()
        status, listing = self.request("/assessments", role="viewer")
        self.assertEqual(status, 200)
        self.assertEqual(listing["assessments"][0]["id"], "assessment-1")
        status, detail = self.request("/assessments/assessment-1", role="viewer")
        self.assertEqual(status, 200)
        serialized = json.dumps(detail)
        self.assertNotIn("should-not-leak", serialized)
        self.assertEqual(detail["findings"][0]["finding_id"], "fn-1")
        status, approvals = self.request("/approvals", role="viewer")
        self.assertEqual(status, 200)
        self.assertIn("approvals", approvals)

    def test_remote_bind_refused_and_short_secrets_rejected(self):
        with self.assertRaises(ValueError):
            OperatorControlServer(("0.0.0.0", 0), runtime_db=self.db,
                                  credentials={"t" * 32: {"operator_id": "a", "role": "admin"}})
        with self.assertRaises(ValueError):
            OperatorControlServer(("127.0.0.1", 0), runtime_db=self.db,
                                  credentials={"short": {"operator_id": "a", "role": "admin"}})

    def test_oversized_body_rejected(self):
        status, body = self.request(f"/jobs/{self.job['id']}/cancel", role="operator", method="POST",
                                    body={"reason": "x" * 9000})
        self.assertEqual(status, 400)
        self.assertIn("request_body_too_large", body["error"])


if __name__ == "__main__": unittest.main()
