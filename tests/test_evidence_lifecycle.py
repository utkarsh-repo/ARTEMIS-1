import json
import pathlib
import tempfile
import unittest
import zipfile

from appsec_agent.evidence import EvidenceStore
from appsec_agent.finding_lifecycle import record_retest, verify_candidate


class EvidenceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.store = EvidenceStore(self.root)

    def add_evidence(self, url="https://staging.example.test/health", status=200):
        return self.store.capture({"method": "GET", "url": url}, status,
                                  {"content-type": "application/json"}, b'{"ok":true}', 5, "fixture")

    def test_manifest_detects_row_modification_and_deletion(self):
        original_id = self.add_evidence()
        self.store.finding({"check": "security_headers", "title": "Header observation",
                            "url": "https://staging.example.test/health", "details": {"missing": "CSP"}, "evidence_id": original_id})
        self.assertTrue(self.store.verify_manifest()["valid"])
        path = self.root / "evidence.jsonl"
        path.write_text(path.read_text().replace('"status":200', '"status":201'))
        self.assertFalse(self.store.verify_manifest()["valid"])

    def test_manifest_detects_tail_deletion(self):
        self.add_evidence()
        self.add_evidence("https://staging.example.test/other")
        path = self.root / "evidence.jsonl"
        path.write_text(path.read_text().splitlines()[0] + "\n")
        self.assertFalse(self.store.verify_manifest()["valid"])

    def test_export_requires_valid_chain_and_contains_manifest(self):
        self.add_evidence()
        destination = self.root / "export.zip"
        manifest = self.store.export_bundle(destination)
        self.assertTrue(manifest["integrity"]["valid"])
        self.assertEqual(manifest["redaction_status"]["evidence_records"], 1)
        with zipfile.ZipFile(destination) as archive:
            self.assertIn("export_manifest.json", archive.namelist())
            self.assertIn("evidence_manifest.jsonl", archive.namelist())
            self.assertIn("traffic.jsonl", archive.namelist())
        (self.root / "evidence.jsonl").write_text("tampered\n")
        with self.assertRaises(ValueError):
            self.store.export_bundle(self.root / "bad.zip")

    def test_independent_verification_and_retest_are_append_only(self):
        original_evidence = self.add_evidence()
        finding_id = self.store.finding({"check": "security_headers", "title": "Missing CSP",
                                         "url": "https://staging.example.test/health", "details": {"missing": ["content-security-policy"]},
                                         "evidence_id": original_evidence})
        verification_evidence = self.add_evidence()
        decision = verify_candidate(self.root, finding_id, verifier_id="headers_recheck",
                                    evidence_id=verification_evidence, outcome="corroborated", rationale="fixture")
        first = record_retest(self.root, finding_id, status="open", evidence_ids=[verification_evidence],
                              reviewer="tester", rationale="Still reproducible")
        second = record_retest(self.root, finding_id, status="remediated", evidence_ids=[original_evidence],
                               reviewer="reviewer", rationale="Recheck passed")
        self.assertEqual(decision["outcome"], "corroborated")
        self.assertEqual((first["version"], second["version"]), (1, 2))
        self.assertEqual(second["previous_retest_id"], first["retest_id"])
        self.assertEqual(len((self.root / "findings.jsonl").read_text().splitlines()), 1)
        self.assertTrue(self.store.verify_manifest()["valid"])
        bundle = self.root / "history.zip"
        self.store.export_bundle(bundle)
        with zipfile.ZipFile(bundle) as archive:
            self.assertIn("verification_history.jsonl", archive.namelist())
            self.assertIn("retest_history.jsonl", archive.namelist())


    def test_caller_cannot_override_deterministic_verifier_outcome(self):
        original = self.add_evidence()
        finding_id = self.store.finding({"check": "security_headers", "title": "Missing CSP",
                                         "url": "https://staging.example.test/health", "details": {"missing": ["content-security-policy"]},
                                         "evidence_id": original})
        retest = self.add_evidence()
        with self.assertRaises(ValueError):
            verify_candidate(self.root, finding_id, verifier_id="headers_recheck", evidence_id=retest,
                             outcome="not_reproduced")

    def test_verification_rejects_unknown_evidence_and_wrong_target(self):
        self.add_evidence()
        # Capture an explicit original record and bind it to the finding.
        original_id = self.add_evidence()
        finding_id = self.store.finding({"check": "security_headers", "title": "Issue",
                                         "url": "https://staging.example.test/health", "details": {}, "evidence_id": original_id})
        wrong_target = self.add_evidence("https://staging.example.test/elsewhere")
        with self.assertRaises(ValueError):
            verify_candidate(self.root, finding_id, verifier_id="headers_recheck", evidence_id="missing",
                             outcome="corroborated")
        with self.assertRaises(ValueError):
            verify_candidate(self.root, finding_id, verifier_id="headers_recheck", evidence_id=wrong_target,
                             outcome="corroborated")


class TrafficJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.store = EvidenceStore(self.root)

    def test_traffic_id_is_persisted_and_bound_to_finding(self):
        evidence_id = self.store.capture(
            {"method": "GET", "url": "https://staging.example.test/health?token=supersecret",
             "headers": {"Authorization": "Bearer verysecret"}},
            200, {"content-type": "application/json"}, b'{"ok":true}', 4, "fixture")
        traffic_id = self.store.traffic_id_for(evidence_id)
        self.assertTrue(traffic_id.startswith("tr-"))
        self.assertTrue(self.store.verify_traffic()["valid"])
        finding_id = self.store.finding({"check": "fixture", "title": "Test finding",
                                         "url": "https://staging.example.test/health",
                                         "evidence_id": evidence_id, "details": {}})
        finding = json.loads((self.root / "findings.jsonl").read_text().splitlines()[0])
        self.assertIsNotNone(finding_id)
        self.assertEqual(finding["traffic_ids"], [traffic_id])
        traffic_text = (self.root / "traffic.jsonl").read_text()
        self.assertNotIn("supersecret", traffic_text)
        self.assertNotIn("verysecret", traffic_text)
        restarted = EvidenceStore(self.root)
        self.assertEqual(restarted.traffic_id_for(evidence_id), traffic_id)
        self.assertTrue(restarted.verify_traffic()["valid"])

    def test_traffic_verifier_detects_missing_and_mismatched_evidence(self):
        evidence_id = self.store.capture({"method": "GET", "url": "https://staging.example.test/"},
                                         200, {}, b"ok", 1, "fixture")
        traffic_path = self.root / "traffic.jsonl"
        row = json.loads(traffic_path.read_text())
        row["evidence_id"] = "ev-missing"
        traffic_path.write_text(json.dumps(row) + "\n")
        result = self.store.verify_traffic()
        self.assertFalse(result["valid"])
        self.assertTrue(any("unresolved_traffic_evidence" in item for item in result["errors"]))

    def test_finding_cannot_supply_unknown_traffic_id(self):
        with self.assertRaises(ValueError):
            self.store.finding({"check": "fixture", "title": "Bad reference", "details": {},
                                "traffic_ids": ["tr-fake"]})

    def test_finding_cannot_attach_a_real_but_unrelated_traffic_id(self):
        evidence_one = self.store.capture({"method": "GET", "url": "https://staging.example.test/one"},
                                          200, {}, b"one", 1, "fixture")
        evidence_two = self.store.capture({"method": "GET", "url": "https://staging.example.test/two"},
                                          200, {}, b"two", 1, "fixture")
        with self.assertRaises(ValueError):
            self.store.finding({"check": "fixture", "title": "Mismatched evidence", "details": {},
                                "evidence_id": evidence_one,
                                "traffic_ids": [self.store.traffic_id_for(evidence_two)]})

    def test_traffic_verifier_detects_tampered_finding_link(self):
        evidence_id = self.store.capture({"method": "GET", "url": "https://staging.example.test/"},
                                         200, {}, b"ok", 1, "fixture")
        finding_id = self.store.finding({"check": "fixture", "title": "Bound finding", "details": {},
                                         "evidence_id": evidence_id})
        self.assertIsNotNone(finding_id)
        path = self.root / "findings.jsonl"
        finding = json.loads(path.read_text().splitlines()[0])
        finding["traffic_ids"] = ["tr-guessed-but-not-real"]
        path.write_text(json.dumps(finding) + "\n")
        result = self.store.verify_traffic()
        self.assertFalse(result["valid"])
        self.assertTrue(any("unknown_finding_traffic_id" in error for error in result["errors"]))

    def test_traffic_ids_are_unique_across_store_restart(self):
        first = self.store.capture({"method": "GET", "url": "https://staging.example.test/"},
                                   200, {}, b"same", 1, "first")
        restarted = EvidenceStore(self.root)
        second = restarted.capture({"method": "GET", "url": "https://staging.example.test/"},
                                    200, {}, b"same", 1, "second")
        self.assertNotEqual(first, second)
        self.assertNotEqual(self.store.traffic_id_for(first), restarted.traffic_id_for(second))
        self.assertTrue(restarted.verify_traffic()["valid"])

    def test_transport_failures_are_recorded_in_traffic_journal(self):
        evidence_id = self.store.capture_transport_error(
            {"method": "GET", "url": "https://staging.example.test/health?api_key=secret",
             "headers": {"Authorization": "Bearer secret"}},
            "ConnectTimeout", 1200, "fixture")
        traffic_id = self.store.traffic_id_for(evidence_id)
        self.assertTrue(traffic_id.startswith("tr-"))
        self.assertTrue(self.store.verify_traffic()["valid"])
        traffic_text = (self.root / "traffic.jsonl").read_text()
        self.assertNotIn("secret", traffic_text)
        finding_id = self.store.finding({"check": "transport", "title": "Connection failed",
                                         "evidence_id": evidence_id, "details": {}})
        self.assertIsNotNone(finding_id)
        finding = json.loads((self.root / "findings.jsonl").read_text().splitlines()[0])
        self.assertEqual(finding["traffic_ids"], [traffic_id])

class AdditionalVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.store = EvidenceStore(self.root)
        self.url = "https://staging.example.test/account"

    def capture(self, status=200, headers=None):
        return self.store.capture({"method": "GET", "url": self.url}, status,
                                  headers or {"content-type": "application/json"}, b'{"ok":true}', 3, "fixture")

    def test_cookie_flags_recheck_uses_only_sanitized_cookie_attribute_metadata(self):
        original = self.capture(headers={"set-cookie": "session=secret; Path=/"})
        finding_id = self.store.finding({"check": "cookie_flags", "title": "Cookie flags missing", "url": self.url,
                                         "details": {"missing_attributes": ["secure", "httponly"]}, "evidence_id": original})
        retest = self.capture(headers={"set-cookie": "session=anothersecret; Path=/"})
        result = verify_candidate(self.root, finding_id, verifier_id="cookie_flags_recheck", evidence_id=retest)
        self.assertEqual(result["outcome"], "corroborated")
        persisted = (self.root / "evidence.jsonl").read_text()
        self.assertNotIn("anothersecret", persisted)
        self.assertIn('"cookie_attributes"', persisted)

    def test_method_surface_recheck_uses_allow_header(self):
        original = self.capture(headers={"allow": "GET, TRACE"})
        finding_id = self.store.finding({"check": "http_method_surface", "title": "Risky method", "url": self.url,
                                         "details": {"methods": ["TRACE"]}, "evidence_id": original})
        retest = self.capture(headers={"allow": "GET, TRACE"})
        result = verify_candidate(self.root, finding_id, verifier_id="http_method_surface_recheck", evidence_id=retest)
        self.assertEqual(result["outcome"], "corroborated")

    def test_anonymous_boundary_recheck_uses_persisted_status(self):
        original = self.capture(status=200)
        finding_id = self.store.finding({"check": "anonymous_auth_boundary", "title": "No auth boundary", "url": self.url,
                                         "details": {"status": 200, "expected": [401, 403]}, "evidence_id": original})
        retest = self.capture(status=403)
        result = verify_candidate(self.root, finding_id, verifier_id="anonymous_auth_boundary_recheck", evidence_id=retest)
        self.assertEqual(result["outcome"], "not_reproduced")

    def test_scenario_status_assertion_recheck_is_evidence_bound(self):
        original = self.capture(status=200)
        finding_id = self.store.finding({"check": "scenario_suite", "title": "Scenario assertion failed", "url": self.url,
                                         "details": {"assertion_type": "status_equals", "expected_status": 201},
                                         "evidence_id": original})
        retest = self.capture(status=200)
        result = verify_candidate(self.root, finding_id, verifier_id="scenario_status_recheck", evidence_id=retest)
        self.assertEqual(result["outcome"], "corroborated")
        passing_retest = self.capture(status=201)
        result = verify_candidate(self.root, finding_id, verifier_id="scenario_status_recheck", evidence_id=passing_retest)
        self.assertEqual(result["outcome"], "not_reproduced")

    def test_scenario_verifier_rejects_unsupported_assertion_as_inconclusive(self):
        original = self.capture(status=200)
        finding_id = self.store.finding({"check": "scenario_suite", "title": "Scenario assertion failed", "url": self.url,
                                         "details": {"assertion_type": "json_path_equals"}, "evidence_id": original})
        retest = self.capture(status=200)
        result = verify_candidate(self.root, finding_id, verifier_id="scenario_status_recheck", evidence_id=retest)
        self.assertEqual(result["outcome"], "inconclusive")

    def test_deterministic_verification_promotes_matching_claim_with_durable_evidence(self):
        from appsec_agent.blackboard import Blackboard
        board = Blackboard(self.root / "blackboard.json")
        original = self.store.capture({"method": "GET", "url": self.url}, 200,
                                     {"content-type": "text/html"}, b"<html>fixture</html>", 2, "original")
        finding_id = self.store.finding({"check": "content_type", "title": "Missing nosniff", "url": self.url,
                                         "details": {}, "evidence_id": original})
        claim_id = board.add_claim("Missing nosniff", claim_type="potential_vulnerability", evidence_ids=[original],
                                   status="pending_verification", provenance={"kind": "security_check_or_import",
                                   "finding_id": finding_id})
        retest = self.store.capture({"method": "GET", "url": self.url}, 200,
                                   {"content-type": "text/html"}, b"<html>fixture</html>", 2, "retest")
        decision = verify_candidate(self.root, finding_id, verifier_id="content_type_recheck", evidence_id=retest)
        self.assertEqual(decision["outcome"], "corroborated")
        self.assertEqual(decision["claim_updates"][0]["claim_id"], claim_id)
        refreshed = Blackboard(self.root / "blackboard.json")
        claim = next(item for item in refreshed.data["claims"] if item["id"] == claim_id)
        self.assertEqual(claim["status"], "verified")
        self.assertIn(retest, claim["evidence_ids"])

    def test_restart_reconciliation_replays_persisted_verification_decision(self):
        from appsec_agent.blackboard import Blackboard
        from appsec_agent.reconciliation import reconcile_assessment
        board = Blackboard(self.root / "blackboard.json")
        original = self.store.capture({"method": "GET", "url": self.url}, 200,
                                     {"content-type": "text/html"}, b"<html>fixture</html>", 2, "original")
        finding_id = self.store.finding({"check": "content_type", "title": "Missing nosniff", "url": self.url,
                                         "details": {}, "evidence_id": original})
        claim_id = board.add_claim("Missing nosniff", evidence_ids=[original], status="pending_verification",
                                   provenance={"finding_id": finding_id})
        retest = self.store.capture({"method": "GET", "url": self.url}, 200,
                                   {"content-type": "text/html"}, b"<html>fixture</html>", 2, "retest")
        self.store.append("verification_history.jsonl", {"verification_id": "vr-crash", "finding_id": finding_id,
            "verifier_id": "content_type_recheck", "evidence_id": retest, "original_evidence_id": original,
            "outcome": "corroborated", "checker_rationale": "fixture", "timestamp": 1})
        result = reconcile_assessment(self.root, board)
        self.assertEqual(result["claim_updates"][0]["claim_id"], claim_id)
        refreshed = Blackboard(self.root / "blackboard.json")
        self.assertEqual(next(c for c in refreshed.data["claims"] if c["id"] == claim_id)["status"], "verified")


if __name__ == "__main__":
    unittest.main()
