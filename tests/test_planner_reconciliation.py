import pathlib
import tempfile
import unittest

from appsec_agent.blackboard import Blackboard
from appsec_agent.evidence import EvidenceStore
from appsec_agent.planner import Planner
from appsec_agent.reconciliation import reconcile_assessment


class PlannerReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.board = Blackboard(self.root / "blackboard.json")

    def test_asset_duplicate_preserves_first_attributes_and_records_conflicts(self):
        asset = self.board.add_asset("canonical", "host", value="staging.example.test",
                                     scope_status="in_scope", attributes={"owner": "team-a", "tier": "staging"})
        again = self.board.add_asset("canonical", "host", value="staging.example.test",
                                     scope_status="out_of_scope", attributes={"owner": "team-b", "region": "ap-south-1"})
        self.assertEqual(asset, again)
        record = self.board.data["assets"][0]
        self.assertEqual(record["attributes"]["owner"], "team-a")
        self.assertEqual(record["attribute_conflicts"]["owner"]["observed"], ["team-b"])
        self.assertTrue(record["scope_conflicts"])
        self.assertEqual(len(record["sightings"]), 1)

    def test_trace_search_filters_and_bounds_limit(self):
        for i in range(5):
            self.board.add_trace(test_id="headers", event_type="observation", summary=f"header event {i}",
                                 intent_id="current" if i == 4 else "prior")
        self.assertEqual(len(self.board.search_traces("header", test_id="headers", exclude_intent_id="current", limit=2)), 2)
        self.assertEqual(len(self.board.search_traces("header", limit=9999)), 5)

    def test_planner_ranking_explains_coverage_and_priority(self):
        candidates = [{"id": "a", "priority": 2, "risk": "low", "kind": "analyze"},
                      {"id": "b", "priority": 4, "risk": "high", "kind": "scenario"}]
        ranked = Planner.rank_candidates(self.board, candidates, [])
        self.assertEqual(ranked[0]["id"], "b")
        self.assertIn("new-kind=10", ranked[0]["_score_reason"])

    def test_reconciliation_reopens_executed_test_without_durable_fact(self):
        self.board.set_test_status("headers", "executed", reason="prior run", result={"ok": True})
        result = reconcile_assessment(self.root, self.board)
        self.assertEqual(result["reopened_for_review"], ["headers"])
        self.assertEqual(self.board.data["test_statuses"]["headers"]["status"], "stale")

    def test_reconciliation_preserves_test_with_persisted_evidence(self):
        store = EvidenceStore(self.root)
        evidence_id = store.capture({"method": "GET", "url": "https://staging.example.test/"}, 200, {}, b"ok", 2, "fixture")
        self.board.add_fact("headers", "response observed", evidence_id, {"status": 200})
        self.board.set_test_status("headers", "executed", reason="prior run", result={"evidence_id": evidence_id})
        result = reconcile_assessment(self.root, self.board)
        self.assertEqual(result["reopened_for_review"], [])
        self.assertEqual(self.board.data["test_statuses"]["headers"]["status"], "executed")


if __name__ == "__main__":
    unittest.main()

    def test_planner_coverage_benchmark_beats_priority_only_baseline(self):
        # Synthetic deterministic benchmark: repeated-category work has higher
        # raw priority, but the explainable coverage gain should select a new
        # category first. This is a planner fixture, not a real scanner benchmark.
        cases = [
            {"observed": ["security_headers", "security_headers_recheck"],
             "candidates": [
                 {"id": "security_headers_recheck", "priority": 20, "risk": "low", "category": "security"},
                 {"id": "api_inventory", "priority": 10, "risk": "medium", "category": "api"}],
             "expected_new_category": "api"},
            {"observed": ["cookie_flags", "cache_policy"],
             "candidates": [
                 {"id": "cookie_retest", "priority": 25, "risk": "low", "category": "cookie"},
                 {"id": "auth_boundary", "priority": 12, "risk": "medium", "category": "auth"}],
             "expected_new_category": "auth"},
            {"observed": ["cors_preflight"],
             "candidates": [
                 {"id": "cors_retest", "priority": 15, "risk": "low", "category": "cors"},
                 {"id": "workflow_invariants", "priority": 8, "risk": "medium", "category": "workflow"}],
             "expected_new_category": "workflow"},
        ]
        covered_by_ranker = 0
        covered_by_priority = 0
        for case in cases:
            board = Blackboard(self.root / (case["expected_new_category"] + ".json"))
            for observed in case["observed"]:
                board.add_trace(test_id=observed, event_type="observation", summary="fixture")
            ranked = Planner.rank_candidates(board, case["candidates"], [])
            naive = sorted(case["candidates"], key=lambda item: (-item["priority"], item["id"]))
            if ranked[0].get("category") == case["expected_new_category"]:
                covered_by_ranker += 1
            if naive[0].get("category") == case["expected_new_category"]:
                covered_by_priority += 1
            self.assertIn("new-kind=", ranked[0]["_score_reason"])
        self.assertEqual(covered_by_ranker, len(cases))
        self.assertGreater(covered_by_ranker, covered_by_priority)
