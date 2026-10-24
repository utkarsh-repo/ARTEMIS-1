import json, pathlib, socket, tempfile, threading, unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from appsec_agent.evidence import EvidenceStore
from appsec_agent.http_client import LabHTTPClient
from appsec_agent.policy import PolicyError

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(body)))
        self.send_header("Set-Cookie","lab_session=example; HttpOnly; Secure; SameSite=Lax")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args): pass

class LocalHTTPTests(unittest.TestCase):
    def test_dns_rebinding_to_private_ip_is_blocked_at_connection_time(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                port = srv.server_address[1]
                policy = {"base_url": f"http://staging.example.test:{port}",
                          "allowed_hosts": ["staging.example.test"], "allowed_path_prefixes": ["/"],
                          "https_only": False, "allow_private_networks": False, "allowed_methods": ["GET"],
                          "allow_state_changing_tests": False, "max_requests": 3,
                          "requests_per_second": 1000, "request_timeout_seconds": 2,
                          "max_response_bytes": 10000, "max_model_observation_chars": 1000}
                original = socket.getaddrinfo
                lookups = {"count": 0}
                def changing_dns(host, requested_port, *args, **kwargs):
                    if host == "staging.example.test":
                        lookups["count"] += 1
                        ip = "8.8.8.8" if lookups["count"] == 1 else "127.0.0.1"
                        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, requested_port))]
                    return original(host, requested_port, *args, **kwargs)
                client = LabHTTPClient(policy, EvidenceStore(pathlib.Path(d)))
                with patch("appsec_agent.policy.socket.getaddrinfo", side_effect=changing_dns):
                    with self.assertRaises(PolicyError):
                        client.request("GET", "/", auth="anonymous", reason="dns-rebinding-test")
                self.assertEqual(lookups["count"], 2)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_request_override_headers_and_read_only_bodies_are_rejected_before_transport(self):
        with tempfile.TemporaryDirectory() as d:
            policy = {"base_url": "https://staging.example.test", "allowed_hosts": ["staging.example.test"],
                      "allowed_path_prefixes": ["/"], "https_only": True, "allow_private_networks": False,
                      "allowed_methods": ["GET", "HEAD", "OPTIONS"], "allow_state_changing_tests": False,
                      "max_requests": 3, "requests_per_second": 1000, "request_timeout_seconds": 2,
                      "max_response_bytes": 10000, "max_model_observation_chars": 1000}
            client = LabHTTPClient(policy, EvidenceStore(pathlib.Path(d)))
            with patch.object(client, "_session") as session:
                for headers in ({"Host": "attacker.example"}, {"Authorization": "Bearer injected"},
                                {"X-HTTP-Method-Override": "DELETE"},
                                {"X-Test": "value\r\nHost: attacker.example"}):
                    with self.assertRaises(PolicyError):
                        client.request("GET", "/", auth="anonymous", headers=headers)
                with self.assertRaises(PolicyError):
                    client.request("GET", "/", auth="anonymous", json_body={"delete": True})
                with self.assertRaises(PolicyError):
                    client.request("GET", "/", auth={"invalid": "profile"})
                session.assert_not_called()
            self.assertEqual(client.used, 0)

    def test_local_request_capture(self):
        srv=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        thread=threading.Thread(target=srv.serve_forever,daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                port=srv.server_address[1]
                policy={"base_url":f"http://127.0.0.1:{port}","allowed_hosts":["127.0.0.1"],
                        "allowed_path_prefixes":["/"],"https_only":False,"allow_private_networks":True,
                        "allowed_methods":["GET"],"allow_state_changing_tests":False,"max_requests":3,
                        "requests_per_second":1000,"request_timeout_seconds":2,"max_response_bytes":10000,
                        "user_agent":"AppSecTest","max_model_observation_chars":1000}
                store=EvidenceStore(pathlib.Path(d))
                client=LabHTTPClient(policy,store)
                obs=client.request("GET","/",auth="anonymous",reason="unit-test")
                self.assertEqual(obs["status"],200)
                self.assertTrue(obs["traffic_id"].startswith("tr-"))
                self.assertTrue(store.verify_traffic()["valid"])
                self.assertEqual(obs["body_sha256"],__import__("hashlib").sha256(b'{"status":"ok"}').hexdigest())
                ev=(pathlib.Path(d)/"evidence.jsonl").read_text()
                self.assertNotIn("lab_session=example",ev)
                self.assertIn("[REDACTED]", ev)
                self.assertIn("body_redacted", ev)
                self.assertEqual(client.used,1)
                store.finding({"check":"unit","title":"Test finding","url":obs["url"],"details":{"status":200},
                               "evidence_id":obs["evidence_id"]})
                store.finding({"check":"unit","title":"Test finding","url":obs["url"],"details":{"status":200},
                               "evidence_id":obs["evidence_id"]})
                lines=(pathlib.Path(d)/"findings.jsonl").read_text().splitlines()
                self.assertEqual(len(lines),1)
                finding = json.loads(lines[0])
                self.assertEqual(finding["traffic_ids"], [obs["traffic_id"]])
        finally:
            srv.shutdown(); srv.server_close()

if __name__=="__main__": unittest.main()

class EngineIntegrationTests(unittest.TestCase):
    def test_offline_run_writes_claims_traces_and_valid_graph(self):
        import json
        from appsec_agent.engine import run
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                port = srv.server_address[1]
                policy = {
                    "base_url": f"http://127.0.0.1:{port}", "allowed_hosts": ["127.0.0.1"],
                    "allowed_path_prefixes": ["/"], "https_only": False, "allow_private_networks": True,
                    "allowed_methods": ["GET"], "allow_state_changing_tests": False, "max_requests": 2,
                    "requests_per_second": 1000, "request_timeout_seconds": 2, "max_response_bytes": 10000,
                    "max_model_observation_chars": 1000, "baseline_paths": ["/"],
                    "security_headers": ["content-security-policy"], "enabled_tests": ["security_headers", "openapi_inventory"],
                    "max_planner_iterations": 2, "max_intents_per_iteration": 1,
                }
                run_dir = pathlib.Path(d) / "run"
                summary = run(policy, run_dir, provider="offline", catalog_path="test_catalog.json")
                board = json.loads((run_dir / "blackboard.json").read_text(encoding="utf-8"))
                validation = json.loads((run_dir / "graph_validation.json").read_text(encoding="utf-8"))
                self.assertTrue(validation["valid"], validation["errors"])
                self.assertTrue(board["assets"])
                self.assertTrue(board["traces"])
                self.assertTrue(board["claims"])
                self.assertTrue(all(c["status"] == "pending_verification" for c in board["claims"]))
                self.assertEqual(board["test_statuses"]["openapi_inventory"]["status"], "deferred")
                self.assertNotIn("openapi_inventory", board["completed_tests"])
                coverage = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
                api_inventory = next(row for row in coverage if row["id"] == "API9:2023")
                self.assertEqual(api_inventory["result"], "deferred")
                report = (run_dir / "report.md").read_text(encoding="utf-8")
                self.assertIn("Claim lifecycle and unresolved questions", report)
                self.assertIn("pending_verification", report)
                self.assertEqual(summary["graph_validation"]["valid"], True)
        finally:
            srv.shutdown()
            srv.server_close()

class ProxyBoundaryTests(unittest.TestCase):
    def test_explicit_proxy_route_is_rejected_before_destination_resolution(self):
        from requests import Request
        from appsec_agent.http_client import _PinnedAddressAdapter
        policy = {"base_url": "https://staging.example.test", "allowed_hosts": ["staging.example.test"],
                  "allowed_path_prefixes": ["/"], "https_only": True, "allow_private_networks": False,
                  "allowed_methods": ["GET"], "allow_state_changing_tests": False}
        adapter = _PinnedAddressAdapter(policy)
        prepared = Request("GET", "https://staging.example.test/health").prepare()
        with patch("appsec_agent.http_client.resolve_target_ips", side_effect=AssertionError("DNS must not run")):
            with self.assertRaises(PolicyError):
                adapter.get_connection_with_tls_context(prepared, verify=True, proxies={"https": "http://proxy.invalid:8080"})
