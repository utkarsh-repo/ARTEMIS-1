from __future__ import annotations
import json, pathlib, time
from .evidence import redact_text

def read_jsonl(path):
    out=[]
    if pathlib.Path(path).exists():
        for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
            try: out.append(json.loads(line))
            except Exception: continue
    return out

def build_coverage(catalog, completed, findings, scenarios, test_statuses=None):
    rows=[]
    test_statuses = test_statuses or {}
    completed_set=set(completed)
    def status_for(test_id):
        status=(test_statuses.get(test_id) or {}).get("status")
        if status is None and test_id in completed_set:
            return "executed"
        return status or "not_run"
    def result_for_tests(test_ids):
        states=[status_for(test_id) for test_id in test_ids]
        if "executed" in states and any(state != "executed" for state in states):
            return "partially_executed"
        for state, label in (("failed", "execution_failed"), ("blocked", "blocked"),
                             ("deferred", "deferred"), ("cancelled", "cancelled"), ("stale", "stale")):
            if state in states:
                return label
        if "running" in states:
            return "in_progress"
        if states and all(state == "executed" for state in states):
            return "executed"
        if "review_only" in states:
            return "review_only"
        return "not_run"
    enabled_scenarios=[s for s in scenarios if s.get("enabled")]
    scenario_ids={s["id"] for s in enabled_scenarios}
    scenario_categories={c for s in enabled_scenarios for c in s.get("category",[])}
    for framework, items in catalog.get("frameworks",{}).items():
        for item in items:
            tests=item.get("tests",[])
            run_tests=[t for t in tests if t in completed_set]
            status=item.get("coverage","unknown")
            if status=="implemented":
                result=result_for_tests(tests)
            elif status=="scenario_required":
                mapped= item.get("id") in scenario_categories
                if mapped:
                    related_ids=[f"scenario:{s['id']}" for s in enabled_scenarios if item.get("id") in s.get("category",[])]
                    related_result=result_for_tests(related_ids)
                    result="scenario_executed" if related_result=="executed" else ("scenario_configured" if related_result=="not_run" else related_result)
                else:
                    related_result=result_for_tests(tests)
                    result=related_result if related_result!="not_run" else "not_run_requires_scenario"
            elif status=="external_tool_required":
                result="external_tool_required"
            elif status=="manual_review_required":
                result="manual_review_required"
            elif status=="partial":
                related_result=result_for_tests(tests)
                result="partial" if related_result=="not_run" else related_result
            else:
                result=result_for_tests(tests)
            rows.append({"framework":framework,"id":item.get("id"),"name":item.get("name"),"coverage_design":status,
                         "result":result,"tests":tests,"test_statuses":{t:status_for(t) for t in tests},
                         "notes":item.get("notes","")})
    return rows

def write_report(run_dir, summary, findings, coverage):
    path=pathlib.Path(run_dir)/"report.md"
    lines=["# Lab Application Security Report","",f"- Run ID: `{summary.get('run_id')}`",f"- Target base: `{summary.get('target')}`",
           f"- Requests sent: {summary.get('requests_used',0)}",f"- Findings: {len(findings)}","",
           "> Coverage labels distinguish executed tests from scenario/code-review requirements. They are not a statement that the entire standard is passed.","",
           "## Findings"]
    if not findings: lines.append("No findings were recorded by the executed checks.")
    for i,f in enumerate(findings,1):
        lines += [f"### {i}. {f.get('title','Untitled finding')}",f"- Severity: **{f.get('severity','info')}**",
                  f"- Confidence: {f.get('confidence','unknown')}",f"- Check: `{f.get('check','unknown')}`",
                  f"- URL: `{f.get('url') or 'not applicable'}`",
                  f"- Evidence: `{f.get('evidence_id') or 'see local evidence file'}`",
                  f"- Standards: {', '.join(f.get('standards',[])) or 'not mapped'}",
                  "",redact_text(str(f.get("details",{}))[:2000]),""]
    # Claims are read from persisted assessment state, not inferred from finding count.
    board_path = pathlib.Path(run_dir) / "blackboard.json"
    board = {}
    if board_path.exists():
        try:
            board = json.loads(board_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            board = {}
    claims = board.get("claims", []) if isinstance(board, dict) else []
    lines += ["", "## Claim lifecycle and unresolved questions", ""]
    claim_counts = summary.get("claim_counts", {})
    if claim_counts:
        lines.append("Claim counts by explicit state: " + ", ".join(f"{key}={value}" for key, value in sorted(claim_counts.items())))
    unresolved = [c for c in claims if c.get("status") not in ("verified", "contradicted")]
    if unresolved:
        lines.append("The following claims remain unresolved and must not be treated as confirmed vulnerabilities:")
        for claim in unresolved[:30]:
            lines.append(f"- `{claim.get('status', 'unknown')}` `{claim.get('id', 'unassigned')}`: {claim.get('text', 'Untitled claim')}")
    else:
        lines.append("No unresolved claim records were present. This is not proof that the target is secure.")
    lines += ["", "## Prioritized summary", ""]
    order={"critical":0,"high":1,"medium":2,"low":3,"info":4}
    ranked=sorted(findings,key=lambda f:(order.get(str(f.get("severity","info")).lower(),5),f.get("check","")))
    for f in ranked[:25]:
        lines.append(f"- **{str(f.get('severity','info')).upper()}** `{f.get('finding_id','unassigned')}` — {f.get('title','Untitled finding')} (confidence: {f.get('confidence','unknown')})")
    if not ranked:
        lines.append("- No findings to prioritize.")
    lines += ["","## Coverage"]
    for framework in sorted({x["framework"] for x in coverage}):
        lines += ["",f"### {framework}"]
        for row in [x for x in coverage if x["framework"]==framework]:
            lines.append(f"- `{row['id']}` {row['name']} — **{row['result']}** (design: {row['coverage_design']})")
            gaps = [(test_id, state) for test_id, state in row.get("test_statuses", {}).items()
                    if state not in ("executed", "not_run")]
            if gaps:
                lines.append("  - Test status details: " + ", ".join(f"`{test_id}`={state}" for test_id, state in gaps))
            if row.get("notes"): lines.append(f"  - {row['notes']}")
    path.write_text("\n".join(lines)+"\n",encoding="utf-8")
    return str(path)
