import json, os, pathlib, tempfile, unittest
from appsec_agent.policy import load_policy, validate_url, PolicyError
from appsec_agent.blackboard import Blackboard, ConcurrentStateWriteError
from appsec_agent.evidence import safe_observation, redact_text, redact_url, redact_payload, EvidenceStore
from appsec_agent.scenarios import validate_scenario

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy={"base_url":"https://staging.example.test","allowed_hosts":["staging.example.test"],
                     "allowed_path_prefixes":["/","/api/"],"https_only":True,"allow_private_networks":True,
                     "allowed_methods":["GET","HEAD","OPTIONS"],"allow_state_changing_tests":False,"max_requests":10}
    def test_allowlisted_url(self):
        self.assertEqual(validate_url(self.policy,"https://staging.example.test/api/health","GET",False),
                         "https://staging.example.test/api/health")
    def test_block_unlisted_host(self):
        with self.assertRaises(PolicyError): validate_url(self.policy,"https://evil.example/api/health","GET",False)
    def test_block_method_by_default(self):
        with self.assertRaises(PolicyError): validate_url(self.policy,"https://staging.example.test/api/x","POST",False)
    def test_block_http(self):
        with self.assertRaises(PolicyError): validate_url(self.policy,"http://staging.example.test/","GET",False)
    def test_block_traversal(self):
        with self.assertRaises(PolicyError): validate_url(self.policy,"https://staging.example.test/api/../admin","GET",False)
    def test_block_credentials_in_url(self):
        with self.assertRaises(PolicyError): validate_url(self.policy,"https://user:pw@staging.example.test/","GET",False)

    def test_block_unapproved_alternate_port(self):
        with self.assertRaises(PolicyError):
            validate_url(self.policy, "https://staging.example.test:8443/api/health", "GET", False)
        custom = dict(self.policy, allowed_ports=[443, 8443])
        self.assertEqual(validate_url(custom, "https://staging.example.test:8443/api/health", "GET", False),
                         "https://staging.example.test:8443/api/health")
        for malformed in ([443, True], [443, 443], [0], [65536]):
            with self.subTest(allowed_ports=malformed), self.assertRaises(PolicyError):
                validate_url(dict(self.policy, allowed_ports=malformed), "https://staging.example.test/api/health", "GET", False)

    def test_block_invalid_ports_fragments_and_ambiguous_urls(self):
        for url in ("https://staging.example.test:99999/api", "https://staging.example.test/api#fragment",
                    "https://staging.example.test\\@evil.example/api", "https://staging.example.test/api\x00x"):
            with self.subTest(url=url), self.assertRaises(PolicyError):
                validate_url(self.policy, url, "GET", False)

    def test_load_policy_rejects_ambiguous_host_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "policy.json"
            policy = {"base_url":"https://staging.example.test", "allowed_hosts":["staging.example.test."],
                      "allowed_path_prefixes":["/"], "allowed_methods":["GET"], "max_requests":1}
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaises(PolicyError):
                load_policy(path)

class BlackboardTests(unittest.TestCase):
    def test_stale_blackboard_writer_cannot_overwrite_newer_state(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "board.json"
            first = Blackboard(path)
            second = Blackboard(path)
            starting_revision = json.loads(path.read_text(encoding="utf-8"))["revision"]
            self.assertEqual(first._persisted_revision, second._persisted_revision)
            self.assertEqual(starting_revision, first._persisted_revision)
            first.add_fact("baseline", "first writer persisted")
            with self.assertRaises(ConcurrentStateWriteError):
                second.add_fact("baseline", "stale writer must not overwrite")
            reloaded = Blackboard(path)
            descriptions = [fact["description"] for fact in reloaded.data["facts"]]
            self.assertIn("first writer persisted", descriptions)
            self.assertNotIn("stale writer must not overwrite", descriptions)

    def test_fact_dedup_and_intent(self):
        with tempfile.TemporaryDirectory() as d:
            b=Blackboard(pathlib.Path(d)/"board.json")
            f1=b.add_fact("baseline","status 200")
            f2=b.add_fact("baseline","status 200")
            self.assertEqual(f1,f2)
            i=b.create_intent("security_headers","check baseline",[f1])
            b.set_intent_status(i,"complete")
            self.assertTrue(b.completed("security_headers"))
            self.assertEqual(len(b.data["facts"]),1)
            with self.assertRaises(ValueError):
                b.create_intent("invalid", "missing fact", ["f-not-present"])



class EvidenceDedupeTests(unittest.TestCase):
    def test_duplicate_findings_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as d:
            ev=EvidenceStore(pathlib.Path(d))
            one=ev.finding({"check":"headers","title":"CSP missing","url":"https://x/","details":{"missing":["csp"]}})
            two=ev.finding({"check":"headers","title":"CSP missing","url":"https://x/","details":{"missing":["csp"]}})
            self.assertIsNotNone(one)
            self.assertIsNone(two)
            records=(pathlib.Path(d)/"findings.jsonl").read_text().splitlines()
            self.assertEqual(len(records),1)

class TodoTests(unittest.TestCase):
    def test_dependency_ordering(self):
        with tempfile.TemporaryDirectory() as d:
            b=Blackboard(pathlib.Path(d)/"board.json")
            first=b.add_todo("baseline")
            second=b.add_todo("auth tests",[first])
            self.assertEqual([x["id"] for x in b.ready_todos()],[first])
            b.update_todo(first,"complete")
            self.assertEqual([x["id"] for x in b.ready_todos()],[second])

class RedactionTests(unittest.TestCase):
    def test_safe_observation_redacts_secret_headers(self):
        result=safe_observation({"url":"https://x/","headers":{"Authorization":"Bearer abcdef1234","Set-Cookie":"session=secret"},"body_excerpt":"token=abcdef1234","_raw_body":b"raw"})
        self.assertNotIn("_raw_body",result)
        self.assertEqual(result["headers"]["Authorization"],"[REDACTED]")
        self.assertIn("[REDACTED]",result["body_excerpt"])

    def test_safe_observation_redacts_nested_json_body_secrets(self):
        result = safe_observation({"url":"https://example.test/?access_token=query-secret",
                                   "body_excerpt":'{"access_token":"body-secret","nested":{"api_key":"nested-secret","ok":true}}'})
        self.assertNotIn("query-secret", result["url"])
        for secret in ("body-secret", "nested-secret"):
            self.assertNotIn(secret, json.dumps(result))
        self.assertIn("true", result["body_excerpt"])


    def test_url_query_secrets_are_redacted(self):
        result = redact_url("https://example.test/api?tenant=demo&access_token=abc123&api-key=secretvalue")
        self.assertIn("tenant=demo", result)
        self.assertNotIn("abc123", result)
        self.assertNotIn("secretvalue", result)

    def test_nested_payload_secrets_are_redacted(self):
        result = redact_payload({"profile": {"email": "user@example.test", "refresh_token": "refresh-secret"},
                                 "items": [{"api_key": "key-secret", "name": "safe"}]})
        serialized = json.dumps(result)
        self.assertNotIn("refresh-secret", serialized)
        self.assertNotIn("key-secret", serialized)
        self.assertIn("user@example.test", serialized)

    def test_evidence_append_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            store = EvidenceStore(pathlib.Path(d))
            with self.assertRaises(ValueError):
                store.append("../outside.jsonl", {"ok": True})

    def test_evidence_append_refuses_symlink_destination(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            store = EvidenceStore(root / "run")
            outside = root / "outside.jsonl"
            outside.write_text("leave-me-alone\n", encoding="utf-8")
            (root / "run" / "events.jsonl").symlink_to(outside)
            with self.assertRaises(OSError):
                store.event({"type": "must-not-follow-link"})
            self.assertEqual(outside.read_text(encoding="utf-8"), "leave-me-alone\n")

    def test_evidence_store_redacts_response_body_and_headers(self):
        with tempfile.TemporaryDirectory() as d:
            store = EvidenceStore(pathlib.Path(d))
            store.capture({"method": "GET", "url": "https://example.test/?token=token-secret",
                           "headers": {"Authorization": "Bearer very-secret-token"}}, 200,
                          {"Set-Cookie": "sid=very-secret-cookie", "Content-Type": "application/json"},
                          b'{"access_token":"body-secret","message":"ok"}', 12.0, "unit")
            record = json.loads((pathlib.Path(d) / "evidence.jsonl").read_text().splitlines()[0])
            serialized = json.dumps(record)
            for secret in ("token-secret", "very-secret-token", "very-secret-cookie", "body-secret"):
                self.assertNotIn(secret, serialized)
            self.assertTrue(record["response"]["body_redacted"])
            self.assertEqual(record["response"]["body_sha256"], __import__("hashlib").sha256(b'{"access_token":"body-secret","message":"ok"}').hexdigest())

class ScenarioTests(unittest.TestCase):
    def test_disabled_scenario_rejected(self):
        p={"base_url":"https://staging.example.test","allowed_hosts":["staging.example.test"],
           "allowed_path_prefixes":["/"],"https_only":True,"allow_private_networks":True,
           "allowed_methods":["GET"],"allow_state_changing_tests":False}
        with self.assertRaises(PolicyError):
            validate_scenario({"id":"x","enabled":False,"safe_for_automation":True,"requests":[{"method":"GET","path":"/"}]},p,False)

if __name__=="__main__": unittest.main()

class BlackboardKnowledgeTests(unittest.TestCase):
    def test_claim_starts_unverified_and_status_history_is_auditable(self):
        with tempfile.TemporaryDirectory() as d:
            board = Blackboard(pathlib.Path(d) / "board.json")
            fact_id = board.add_fact("headers", "CSP header absent", "ev-1", {"url": "https://staging.example.test/"},
                                     provenance={"kind": "http_observation", "source": "security_headers"})
            claim_id = board.add_claim("Potential missing CSP", claim_type="potential_vulnerability",
                                       supporting_fact_ids=[fact_id], evidence_ids=["ev-1"],
                                       status="pending_verification", confidence="heuristic")
            claim = next(x for x in board.data["claims"] if x["id"] == claim_id)
            self.assertEqual(claim["status"], "pending_verification")
            board.update_claim_status(claim_id, "verified", reviewer="unit-test", rationale="Independent fixture check",
                                      evidence_ids=["ev-2"])
            claim = next(x for x in board.data["claims"] if x["id"] == claim_id)
            self.assertEqual(claim["status"], "verified")
            self.assertEqual(claim["version"], 2)
            self.assertEqual(claim["status_history"][-1]["reviewer"], "unit-test")
            self.assertEqual(set(claim["evidence_ids"]), {"ev-1", "ev-2"})
            self.assertTrue(board.validate_graph()["valid"])

    def test_claim_status_is_validated(self):
        with tempfile.TemporaryDirectory() as d:
            board = Blackboard(pathlib.Path(d) / "board.json")
            with self.assertRaises(ValueError):
                board.add_claim("unsupported", status="confirmed_by_vibes")
            with self.assertRaises(ValueError):
                board.add_claim("must not self-verify", status="verified", evidence_ids=["ev-1"])
            with self.assertRaises(ValueError):
                board.add_claim("dangling fact", supporting_fact_ids=["f-does-not-exist"])

    def test_verified_status_requires_reviewer_and_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            board = Blackboard(pathlib.Path(d) / "board.json")
            claim_id = board.add_claim("Potential issue", status="pending_verification")
            with self.assertRaises(ValueError):
                board.update_claim_status(claim_id, "verified")
            with self.assertRaises(ValueError):
                board.update_claim_status(claim_id, "verified", reviewer="human-reviewer")
            board.update_claim_status(claim_id, "verified", reviewer="deterministic-verifier", evidence_ids=["ev-proof"])
            claim = next(x for x in board.data["claims"] if x["id"] == claim_id)
            self.assertEqual(claim["status"], "verified")

    def test_asset_dedup_preserves_sightings(self):
        with tempfile.TemporaryDirectory() as d:
            board = Blackboard(pathlib.Path(d) / "board.json")
            one = board.add_asset("https://staging.example.test", "application", value="https://staging.example.test",
                                  provenance={"kind": "policy"})
            two = board.add_asset("https://staging.example.test", "application", value="https://staging.example.test",
                                  provenance={"kind": "baseline"})
            self.assertEqual(one, two)
            asset = board.data["assets"][0]
            self.assertEqual(len(asset["sightings"]), 1)
            self.assertEqual(asset["scope_status"], "in_scope")

    def test_trace_search_can_exclude_current_intent(self):
        with tempfile.TemporaryDirectory() as d:
            board = Blackboard(pathlib.Path(d) / "board.json")
            board.add_trace(intent_id="i-current", test_id="cors_preflight", summary="CORS allow origin wildcard")
            board.add_trace(intent_id="i-prior", test_id="cors_preflight", summary="CORS allow origin restricted")
            found = board.search_traces("CORS origin", exclude_intent_id="i-current")
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["intent_id"], "i-prior")

    def test_todo_rejects_missing_dependencies_and_invalid_status(self):
        with tempfile.TemporaryDirectory() as d:
            board = Blackboard(pathlib.Path(d) / "board.json")
            with self.assertRaises(ValueError):
                board.add_todo("dependent", ["missing-id"])
            todo_id = board.add_todo("first")
            with self.assertRaises(ValueError):
                board.update_todo(todo_id, "completed-ish")

    def test_legacy_blackboard_migrates_without_losing_facts(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "board.json"
            path.write_text(json.dumps({"schema_version": "1.1", "facts": [{"id": "f-old", "test_id": "baseline",
                "description": "legacy fact", "confidence": "high", "ts": 1}], "intents": [], "hints": [],
                "edges": [], "completed_tests": [], "todos": []}), encoding="utf-8")
            board = Blackboard(path)
            self.assertEqual(board.data["schema_version"], "2.0")
            self.assertEqual(board.data["facts"][0]["id"], "f-old")
            self.assertEqual(board.data["facts"][0]["verification_status"], "observed")
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["facts"][0]["id"], "f-old")

    def test_corrupt_blackboard_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "board.json"
            path.write_text("{invalid", encoding="utf-8")
            with self.assertRaises(ValueError):
                Blackboard(path)
            self.assertEqual(path.read_text(encoding="utf-8"), "{invalid")

    def test_newer_schema_is_not_downgraded(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "board.json"
            path.write_text(json.dumps({"schema_version":"99.0", "facts":[], "intents":[]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "newer than supported"):
                Blackboard(path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schema_version"], "99.0")


class PolicyPathBoundaryTests(unittest.TestCase):
    def test_prefix_requires_path_boundary(self):
        p = {"base_url": "https://staging.example.test", "allowed_hosts": ["staging.example.test"],
             "allowed_path_prefixes": ["/api"], "https_only": True, "allow_private_networks": True,
             "allowed_methods": ["GET"], "allow_state_changing_tests": False}
        self.assertEqual(validate_url(p, "https://staging.example.test/api/users", "GET", False),
                         "https://staging.example.test/api/users")
        with self.assertRaises(PolicyError):
            validate_url(p, "https://staging.example.test/apix/users", "GET", False)

    def test_double_encoded_traversal_is_blocked(self):
        p = {"base_url": "https://staging.example.test", "allowed_hosts": ["staging.example.test"],
             "allowed_path_prefixes": ["/api/"], "https_only": True, "allow_private_networks": True,
             "allowed_methods": ["GET"], "allow_state_changing_tests": False}
        for path in ("/api/%252e%252e/admin", "/api/%2e%2e/admin", "/api/%252f..%252fadmin"):
            with self.subTest(path=path), self.assertRaises(PolicyError):
                validate_url(p, "https://staging.example.test" + path, "GET", False)


class CoverageStatusTests(unittest.TestCase):
    def test_coverage_distinguishes_deferred_from_executed(self):
        from appsec_agent.report import build_coverage
        catalog = {"frameworks": {"test": [{"id":"T1", "name":"Headers", "coverage":"implemented",
                    "tests":["security_headers", "cookie_flags"]}]}}
        rows = build_coverage(catalog, ["security_headers"], [], [],
                              test_statuses={"security_headers":{"status":"executed"},
                                             "cookie_flags":{"status":"deferred", "reason":"no baseline"}})
        self.assertEqual(rows[0]["result"], "partially_executed")
        self.assertEqual(rows[0]["test_statuses"]["cookie_flags"], "deferred")

    def test_coverage_does_not_call_missing_configuration_executed(self):
        from appsec_agent.report import build_coverage
        catalog = {"frameworks": {"test": [{"id":"T1", "name":"API inventory", "coverage":"implemented",
                    "tests":["openapi_inventory"]}]}}
        rows = build_coverage(catalog, [], [], [], test_statuses={"openapi_inventory":{"status":"deferred"}})
        self.assertEqual(rows[0]["result"], "deferred")
