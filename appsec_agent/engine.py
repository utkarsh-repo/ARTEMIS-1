from __future__ import annotations
import json, pathlib, time
from .blackboard import Blackboard
from .checks import (analyze_headers,analyze_cookies,analyze_disclosure,analyze_cache,
                     analyze_content_type,analyze_error,run_cors,run_method_surface,analyze_anonymous_boundary)
from .evidence import EvidenceStore
from .http_client import LabHTTPClient, RequestBudgetExceeded
from .openapi_inventory import inventory
from .planner import Planner
from .report import read_jsonl, build_coverage, write_report
from .scenarios import load_scenarios, run_scenario
from .sarif import import_sarif

def _safe_result_summary(result):
    """Keep traces/blackboard facts small and free of raw response content."""
    if not isinstance(result, dict):
        return {"result_type": type(result).__name__}
    out = {}
    for key in ("executed", "deferred", "evidence_id", "operation_count", "scenarios", "review_only", "error"):
        if key in result and isinstance(result[key], (str, int, float, bool, type(None))):
            out[key] = result[key]
    results = result.get("results")
    if isinstance(results, dict):
        safe_results = {}
        for name, observation in list(results.items())[:100]:
            if isinstance(observation, dict):
                safe_results[str(name)[:100]] = {k: observation.get(k) for k in
                    ("url", "method", "status", "evidence_id", "transport_error", "truncated") if k in observation}
            else:
                safe_results[str(name)[:100]] = {"result_type": type(observation).__name__}
        out["results"] = safe_results
    return out


def _execute_registered_test(test_id, *, latest, target, client, policy, store, scenarios, workflow, openapi_path):
    """Dispatch a registered test ID to deterministic code; no model supplied requests are accepted."""
    if test_id == "security_headers":
        if latest: analyze_headers(latest[-1],policy,store)
        return {"executed": bool(latest)}
    if test_id == "cookie_flags":
        if latest: analyze_cookies(latest[-1],store)
        return {"executed": bool(latest)}
    if test_id == "technology_disclosure":
        if latest: analyze_disclosure(latest[-1],store)
        return {"executed": bool(latest)}
    if test_id == "cache_policy":
        if latest: analyze_cache(latest[-1],store)
        return {"executed": bool(latest)}
    if test_id == "content_type":
        if latest: analyze_content_type(latest[-1],policy,store)
        return {"executed": bool(latest)}
    if test_id == "error_surface":
        if latest: analyze_error(latest[-1],store)
        return {"executed": bool(latest)}
    if test_id == "cors_preflight":
        obs=run_cors(client,target,store); latest.append(obs)
        return {"executed": True,"evidence_id":obs.get("evidence_id")}
    if test_id == "http_method_surface":
        obs=run_method_surface(client,target,store); latest.append(obs)
        return {"executed": True,"evidence_id":obs.get("evidence_id")}
    if test_id == "anonymous_auth_boundary":
        if not policy.get("protected_paths"):
            store.event({"type":"check_deferred","check":test_id,"reason":"no protected_paths configured"})
            return {"executed":False,"deferred":True}
        analyze_anonymous_boundary(client,policy["protected_paths"],store)
        return {"executed":True}
    if test_id == "openapi_inventory":
        if not openapi_path:
            store.event({"type":"check_deferred","check":test_id,"reason":"no OpenAPI file supplied"})
            return {"executed":False,"deferred":True}
        inv=inventory(openapi_path,policy,store,client if policy.get("probe_openapi_gets") else None)
        return {"executed":True,"operation_count":inv.get("operation_count",0)}
    if test_id == "scenario_suite":
        enabled=[x for x in scenarios if x.get("enabled",False)]
        if not enabled:
            store.event({"type":"check_deferred","check":test_id,"reason":"no enabled scenarios"})
            return {"executed":False,"deferred":True}
        results=[]
        for scenario in enabled:
            result=run_scenario(scenario,client,policy,store)
            results.append(result)
            for obs in result.get("results",{}).values():
                if isinstance(obs,dict): latest.append(obs)
        return {"executed":True,"scenarios":len(results)}
    if test_id == "workflow_invariants":
        if not workflow:
            store.event({"type":"check_deferred","check":test_id,"reason":"no workflow file"})
            return {"executed":False,"deferred":True}
        for inv in workflow.get("invariants",[]):
            store.finding({"timestamp":time.time(),"check":"workflow_invariants","title":"Business invariant requires executable fixture",
                "severity":"info","confidence":"low","url":None,"standards":[inv.get("id")],
                "details":{"statement":inv.get("statement"),"verification":inv.get("verification"),"executed":False}})
        return {"executed":True,"review_only":True}
    if test_id.startswith("scenario:"):
        sid=test_id.split(":",1)[1]
        scenario=next(x for x in scenarios if x["id"]==sid and x.get("enabled"))
        result=run_scenario(scenario,client,policy,store)
        for obs in result.get("results",{}).values():
            if isinstance(obs,dict): latest.append(obs)
        return result
    raise ValueError("Unregistered test ID: "+str(test_id))

def run(policy, run_dir, *, provider="offline", openapi_path=None, scenarios_path=None, workflow_path=None,
        catalog_path="test_catalog.json", sarif_paths=None, max_iterations=None, hints=None):
    run_dir=pathlib.Path(run_dir)
    # Hosted-provider budgets and the durable ledger are validated before the
    # engine makes any target requests, not lazily at the first planner call.
    budget_path = run_dir / "model_budget.json"
    planner=Planner(provider,policy.get("max_intents_per_iteration",3),
                    budget_config=policy.get("llm_budget"),
                    budget_path=budget_path if provider != "offline" else None)
    store=EvidenceStore(run_dir)
    board=Blackboard(run_dir/"blackboard.json")
    from .reconciliation import reconcile_assessment
    reconciliation = reconcile_assessment(run_dir, board)
    store.event({"type": "restart_reconciliation", **reconciliation})
    asset_id=board.add_asset(
        canonical_id=policy["base_url"], asset_type="application",
        value=policy["base_url"], scope_status="in_scope",
        provenance={"kind":"operator_policy", "source":"policy.json"},
        attributes={"allowed_hosts":policy.get("allowed_hosts", []), "allowed_path_prefixes":policy.get("allowed_path_prefixes", [])})
    for hint in (hints or []): board.add_hint(hint, source="operator")
    catalog=json.loads(pathlib.Path(catalog_path).read_text(encoding="utf-8"))
    tests=[t for t in catalog["runnable_tests"] if t["id"] in policy.get("enabled_tests",[])]
    scenarios=load_scenarios(scenarios_path)
    workflow=json.loads(pathlib.Path(workflow_path).read_text(encoding="utf-8")) if workflow_path and pathlib.Path(workflow_path).exists() else None
    client=LabHTTPClient(policy,store,assessment_id=run_dir.name)
    inventory_result={"paths":[],"operations":0}
    if openapi_path:
        inventory_result=inventory(openapi_path,policy,store,client if policy.get("probe_openapi_gets") else None)
        board.add_fact("openapi_inventory",f"OpenAPI inventory processed {inventory_result.get('operation_count',0)} operations",None,
                       {"path_count":inventory_result.get("path_count"),"operation_count":inventory_result.get("operation_count")},confidence="high")
    sarif_count=import_sarif(sarif_paths,store) if sarif_paths else 0
    latest=[]
    # Baseline requests are explicitly declared in the policy.
    for path in policy.get("baseline_paths",["/"]):
        try:
            obs=client.request("GET",path,reason="baseline")
            latest.append(obs)
            fact_id=board.add_fact("baseline",f"Baseline response for {path}: status={obs.get('status')}",obs.get("evidence_id"),
                           {"url":obs.get("url"),"status":obs.get("status")},confidence="high",
                           provenance={"kind":"http_observation", "reason":"baseline", "timestamp":time.time()},
                           verification_status="observed", asset_id=asset_id)
            board.add_trace(test_id="baseline", event_type="observation",
                            summary=f"Baseline response for {path}: status={obs.get('status')}",
                            asset_id=asset_id, evidence_ids=[obs.get("evidence_id")] if obs.get("evidence_id") else [],
                            details={"path":path, "status":obs.get("status")})
            for check_id,fn in [
                ("security_headers",lambda:analyze_headers(obs,policy,store)),
                ("cookie_flags",lambda:analyze_cookies(obs,store)),
                ("technology_disclosure",lambda:analyze_disclosure(obs,store)),
                ("cache_policy",lambda:analyze_cache(obs,store)),
                ("content_type",lambda:analyze_content_type(obs,policy,store)),
                ("error_surface",lambda:analyze_error(obs,store))
            ]:
                if check_id in policy.get("enabled_tests",[]):
                    fn()
                    board.set_test_status(check_id, "executed", reason="deterministic check evaluated baseline response")
            board.save()
        except Exception as exc:
            board.set_test_status("baseline", "failed", reason=type(exc).__name__)
            store.event({"type":"baseline_blocked","path":path,"error":type(exc).__name__})
        if client.server_errors>=int(policy.get("stop_on_5xx",3)): break
    target=latest[0]["url"] if latest and latest[0].get("url") else policy["base_url"].rstrip("/")+"/"
    # Run core request observations before entering the planner loop.
    for test_id in ("cors_preflight","http_method_surface"):
        if test_id in policy.get("enabled_tests",[]) and client.server_errors<int(policy.get("stop_on_5xx",3)):
            try:
                result=_execute_registered_test(test_id,latest=latest,target=target,client=client,policy=policy,
                    store=store,scenarios=scenarios,workflow=workflow,openapi_path=openapi_path)
                board.set_test_status(test_id, "executed", reason="registered HTTP observation completed", result=_safe_result_summary(result))
                if result.get("evidence_id"):
                    board.add_fact(test_id,f"{test_id} response recorded",result["evidence_id"],result,confidence="medium")
                board.save()
            except Exception as exc:
                board.set_test_status(test_id, "failed", reason=type(exc).__name__)
                store.event({"type":"check_skipped","check":test_id,"error":type(exc).__name__})
    # Include app-specific scenario IDs as planner candidates.
    enabled_scenarios=[sc for sc in scenarios if sc.get("enabled")]
    all_tests=list(tests)
    for scenario in enabled_scenarios:
        all_tests.append({"id":"scenario:"+scenario["id"],"name":scenario.get("description",scenario["id"]),
                          "risk":"configured","kind":"scenario","priority":9})
    iterations=0; limit=max_iterations or int(policy.get("max_planner_iterations",30))
    while iterations<limit and client.used<int(policy["max_requests"]) and client.server_errors<int(policy.get("stop_on_5xx",3)):
        iterations+=1
        decision=planner.decide(board,all_tests,latest)
        store.event({"type":"planner_decision","iteration":iterations,"provider":provider,
                     "summary":decision.get("summary"),"candidate_intents":decision.get("intents",[])})
        board.add_trace(event_type="planner_decision", worker_id="planner", summary=decision.get("summary", ""),
                        asset_id=asset_id, details={"iteration":iterations, "provider":provider,
                        "candidate_intents":decision.get("intents", [])})
        if decision.get("budget_stopped"):
            store.event({"type":"model_budget_exhausted", "iteration":iterations, "provider":provider})
            break
        if decision.get("complete") or not decision.get("intents"): break
        progressed=False
        for proposal in decision["intents"]:
            test_id=proposal["test_id"]
            if board.completed(test_id): continue
            recent_fact_ids=[f["id"] for f in board.data["facts"][-5:]]
            intent_id=board.create_intent(test_id,proposal.get("reason","planner selection"),recent_fact_ids)
            for fid in recent_fact_ids: board.add_edge(fid,intent_id,"supports_intent")
            board.set_intent_status(intent_id,"running")
            board.set_test_status(test_id, "running", reason="planner dispatched registered test")
            try:
                result=_execute_registered_test(test_id,latest=latest,target=target,client=client,policy=policy,
                    store=store,scenarios=scenarios,workflow=workflow,openapi_path=openapi_path)
                if isinstance(result, dict) and result.get("deferred"):
                    reason = str(result.get("reason") or "Required configuration is missing")
                    board.set_intent_status(intent_id, "blocked", {"test_id":test_id, "deferred":True, "reason":reason})
                    board.set_test_status(test_id, "deferred", reason=reason, result=_safe_result_summary(result))
                    board.add_trace(intent_id=intent_id, test_id=test_id, event_type="test_deferred",
                                    summary=f"Test deferred: {test_id}", asset_id=asset_id,
                                    details={"reason":reason})
                    store.event({"type":"test_deferred", "test_id":test_id, "reason":reason})
                    continue
                if isinstance(result, dict) and result.get("executed") is False:
                    reason = "Registered test did not execute and did not provide a deferred reason"
                    board.set_intent_status(intent_id, "failed", {"test_id":test_id, "reason":reason})
                    board.set_test_status(test_id, "failed", reason=reason, result=_safe_result_summary(result))
                    store.event({"type":"test_failed", "test_id":test_id, "reason":reason})
                    continue
                evidence_ref=result.get("evidence_id") if isinstance(result,dict) else None
                fact_id=board.add_fact(test_id,f"Registered check completed: {test_id}",evidence_ref,
                                       {"result":_safe_result_summary(result)},confidence="medium",
                                       provenance={"kind":"registered_test", "test_id":test_id, "intent_id":intent_id},
                                       verification_status="observed", asset_id=asset_id)
                board.add_trace(intent_id=intent_id, test_id=test_id, event_type="test_result",
                                summary=f"Registered check completed: {test_id}", asset_id=asset_id,
                                evidence_ids=[evidence_ref] if evidence_ref else [],
                                details={"result":_safe_result_summary(result)})
                board.add_edge(intent_id,fact_id,"yields_fact")
                board.set_intent_status(intent_id,"complete",{"test_id":test_id,"result":_safe_result_summary(result)})
                if isinstance(result, dict) and result.get("review_only"):
                    board.set_test_status(test_id, "review_only", reason="Workflow invariants were registered for human review, not executed", result=_safe_result_summary(result))
                else:
                    board.set_test_status(test_id, "executed", reason="Registered test execution completed", result=_safe_result_summary(result))
                if test_id=="scenario_suite":
                    for sc in enabled_scenarios:
                        scenario_test_id="scenario:"+sc["id"]
                        board.set_test_status(scenario_test_id, "executed", reason="Scenario executed by scenario_suite")
                board.save()
                progressed=True
            except RequestBudgetExceeded as exc:
                board.set_intent_status(intent_id,"blocked",{"error":type(exc).__name__})
                board.set_test_status(test_id, "blocked", reason=type(exc).__name__)
                store.event({"type":"test_blocked","test_id":test_id,"error":type(exc).__name__})
            except Exception as exc:
                board.set_intent_status(intent_id,"failed",{"error":type(exc).__name__})
                board.set_test_status(test_id, "failed", reason=type(exc).__name__)
                store.event({"type":"test_failed","test_id":test_id,"error":type(exc).__name__})
            if client.used>=int(policy["max_requests"]) or client.server_errors>=int(policy.get("stop_on_5xx",3)): break
        if not progressed and all(board.completed(t["id"]) for t in all_tests):
            break
        # Missing prerequisites are deferred, never counted as executed coverage.
        for tid, missing in {
            "openapi_inventory": not openapi_path,
            "scenario_suite": not enabled_scenarios,
            "anonymous_auth_boundary": not policy.get("protected_paths"),
            "workflow_invariants": not workflow
        }.items():
            if missing and tid in [t["id"] for t in all_tests] and board.data.get("test_statuses", {}).get(tid, {}).get("status") is None:
                board.set_test_status(tid, "deferred", reason="Required input/configuration was not supplied")
        board.save()
    findings=__import__("appsec_agent.report",fromlist=["read_jsonl"]).read_jsonl(run_dir/"findings.jsonl")
    # Scanner/check findings enter the claim lifecycle as candidates, never as verified by default.
    fact_by_evidence={f.get("evidence_id"):f.get("id") for f in board.data.get("facts",[]) if f.get("evidence_id")}
    for finding in findings:
        evidence_id=finding.get("evidence_id")
        supporting=[fact_by_evidence[evidence_id]] if evidence_id in fact_by_evidence else []
        board.add_claim(
            finding.get("title", "Untitled security finding"), claim_type="potential_vulnerability",
            asset_id=asset_id, supporting_fact_ids=supporting,
            evidence_ids=[evidence_id] if evidence_id else [], status="pending_verification",
            provenance={"kind":"security_check_or_import", "source":finding.get("check", "unknown"),
                        "finding_id":finding.get("finding_id")},
            confidence=finding.get("confidence", "heuristic"),
            rationale="Candidate imported from a check or scanner; independent verification has not been implied.",
            limitations=["Finding status is not independently verified by the planner."])
    graph_validation=board.validate_graph()
    store.event({"type":"blackboard_graph_validation", **graph_validation})
    (run_dir/"graph_validation.json").write_text(json.dumps(graph_validation,indent=2)+"\n",encoding="utf-8")
    coverage=build_coverage(catalog,board.data.get("completed_tests",[]),findings,scenarios,
                            test_statuses=board.data.get("test_statuses",{}))
    (run_dir/"coverage.json").write_text(json.dumps(coverage,indent=2)+"\n",encoding="utf-8")
    summary={"run_id":run_dir.name,"finished_at":time.time(),"target":policy["base_url"],"provider":provider,
             "requests_used":client.used,"request_budget":policy["max_requests"],"server_errors":client.server_errors,
             "model_budget": planner.budget.snapshot() if planner.budget else None,
             "observations":len(latest),"planner_iterations":iterations,"findings_count":len(findings),
             "sarif_findings_imported":sarif_count,"openapi_operations":inventory_result.get("operation_count",0),
             "completed_tests":board.data.get("completed_tests",[]),
             "test_statuses":{k:v.get("status") for k,v in board.data.get("test_statuses",{}).items()},
             "claim_counts":{status:sum(1 for c in board.data.get("claims",[]) if c.get("status")==status)
                             for status in ("observed","hypothesized","pending_verification","verified","contradicted","inconclusive","stale")},
             "graph_validation":graph_validation,
             "evidence":"evidence.jsonl","findings":"findings.jsonl",
             "coverage":"coverage.json","blackboard":"blackboard.json"}
    (run_dir/"run_summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    from .report import write_report
    write_report(run_dir,summary,findings,coverage)
    return summary
