from __future__ import annotations
import json, os, re, time
from pathlib import Path
from .policy import STATE_CHANGING, validate_url, PolicyError

VAR = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")

def expand(value):
    if isinstance(value,str):
        def repl(m):
            name=m.group(1)
            if name not in os.environ:
                raise ValueError(f"Required scenario variable {name} is not set")
            return os.environ[name]
        return VAR.sub(repl,value)
    if isinstance(value,list): return [expand(v) for v in value]
    if isinstance(value,dict): return {k:expand(v) for k,v in value.items()}
    return value

def load_scenarios(path):
    if not path or not Path(path).exists(): return []
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    items=data.get("scenarios",[])
    ids=[x.get("id") for x in items]
    if len(ids)!=len(set(ids)): raise ValueError("Scenario IDs must be unique")
    return items

def _json_path(obj, path):
    cur=obj
    for part in path.strip("$.").split("."):
        if not part: continue
        if isinstance(cur,dict): cur=cur.get(part)
        elif isinstance(cur,list):
            try: cur=cur[int(part)]
            except Exception: return None
        else: return None
    return cur

def validate_scenario(scenario, policy, check_dns=True):
    if not scenario.get("enabled",False): raise PolicyError("Scenario is disabled")
    if not scenario.get("safe_for_automation",False): raise PolicyError("Scenario not marked safe_for_automation")
    reqs=scenario.get("requests",[])
    if not reqs: raise PolicyError("Scenario has no requests")
    stateful=any(r.get("method","GET").upper() in STATE_CHANGING for r in reqs)
    if stateful:
        if not scenario.get("disposable_test_data",False): raise PolicyError("State-changing scenario must declare disposable_test_data=true")
        if not scenario.get("cleanup"): raise PolicyError("State-changing scenario must include cleanup steps")
        if not policy.get("allow_state_changing_tests",False): raise PolicyError("State-changing tests disabled in policy")
        if os.environ.get("APPSEC_LAB_ACK_STATE_CHANGES")!="I_ACKNOWLEDGE_DISPOSABLE_LAB_DATA":
            raise PolicyError("Set APPSEC_LAB_ACK_STATE_CHANGES to acknowledge disposable lab data")
    for step in reqs + (scenario.get("cleanup",[]) if stateful else []):
        method=step.get("method","GET").upper()
        if method not in policy["allowed_methods"]: raise PolicyError(f"Method {method} not allowed by policy")
        path=expand(step.get("path","/"))
        base=policy["base_url"].rstrip("/")+"/"
        from urllib.parse import urljoin
        validate_url(policy,urljoin(base,path.lstrip("/")),method,resolve_dns=check_dns)
    return True

def run_scenario(scenario, client, policy, store):
    """Execute only developer-authored steps. Cleanup always runs in finally for stateful scenarios."""
    validate_scenario(scenario,policy)
    results={}
    stateful=any(r.get("method","GET").upper() in STATE_CHANGING for r in scenario.get("requests",[]))
    failure=None
    try:
        for step in scenario["requests"]:
            payload=expand(step)
            method=payload.get("method","GET").upper()
            obs=client.request(method,payload["path"],auth=payload.get("auth","default"),
                headers=payload.get("headers"),json_body=payload.get("json"),body=payload.get("body"),
                reason=f"scenario:{scenario['id']}:{payload.get('name','step')}")
            results[payload.get("name",str(len(results)))]=obs
            store.event({"type":"scenario_step","scenario":scenario["id"],"step":payload.get("name"),"status":obs.get("status"),"evidence_id":obs.get("evidence_id")})
            if client.server_errors>=int(policy.get("stop_on_5xx",3)):
                raise RuntimeError("Stopped after repeated server errors")
        assertions=[]
        for a in scenario.get("assertions",[]):
            step_name=a.get("step")
            obs=results.get(step_name,{})
            passed=False; detail={}
            typ=a.get("type")
            if typ=="status_in":
                passed=obs.get("status") in a.get("values",[]); detail={"actual":obs.get("status"),"expected":a.get("values")}
            elif typ=="status_equals":
                passed=obs.get("status")==a.get("value"); detail={"actual":obs.get("status"),"expected":a.get("value")}
            elif typ=="status_not_equals":
                passed=obs.get("status")!=a.get("value"); detail={"actual":obs.get("status"),"not_expected":a.get("value")}
            elif typ=="json_path_equals":
                try: value=__import__("json").loads(obs.get("_body_text",""))
                except Exception: value={}
                actual=_json_path(value,a.get("path","$"))
                expected=expand(a.get("value"))
                actual_text=json.dumps(actual,sort_keys=True,default=str)
                expected_text=json.dumps(expected,sort_keys=True,default=str)
                passed=actual==expected; detail={"path":a.get("path"),"actual_type":type(actual).__name__,
                    "actual_sha256":__import__("hashlib").sha256(actual_text.encode()).hexdigest(),
                    "expected_type":type(expected).__name__,
                    "expected_sha256":__import__("hashlib").sha256(expected_text.encode()).hexdigest()}
            elif typ=="json_path_in":
                try: value=__import__("json").loads(obs.get("_body_text",""))
                except Exception: value={}
                actual=_json_path(value,a.get("path","$"))
                actual_text=json.dumps(actual,sort_keys=True,default=str)
                passed=actual in a.get("values",[]); detail={"path":a.get("path"),"actual_type":type(actual).__name__,
                    "actual_sha256":__import__("hashlib").sha256(actual_text.encode()).hexdigest(),
                    "allowed_values_count":len(a.get("values",[]))}
            elif typ=="body_not_contains":
                value=expand(a.get("value",""))
                body=obs.get("_body_text","")
                passed=value not in body; detail={"needle":"[configured value]","body_sha256":obs.get("body_sha256")}
            elif typ=="same_status_as":
                other=results.get(a.get("other_step"),{})
                passed=obs.get("status")==other.get("status"); detail={"actual":obs.get("status"),"other":other.get("status")}
            elif typ=="different_status_from":
                other=results.get(a.get("other_step"),{})
                passed=obs.get("status")!=other.get("status"); detail={"actual":obs.get("status"),"other":other.get("status")}
            else:
                detail={"error":"unsupported assertion type"}
            result={"scenario":scenario["id"],"assertion":a,"passed":bool(passed),"details":detail,"evidence_id":obs.get("evidence_id"),"timestamp":time.time()}
            assertions.append(result)
            if not passed:
                # Preserve only a small status-code assertion contract for a
                # later independent retest. Never persist arbitrary expanded
                # assertion values (which may contain credentials or PII).
                verification_detail = dict(detail)
                if typ in {"status_equals", "status_not_equals"} and isinstance(a.get("value"), int) and not isinstance(a.get("value"), bool) and 100 <= a["value"] <= 599:
                    verification_detail["assertion_type"] = typ
                    verification_detail["expected_status"] = a["value"]
                elif typ == "status_in" and isinstance(a.get("values"), list) and a["values"] and len(a["values"]) <= 20 and all(isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599 for v in a["values"]):
                    verification_detail["assertion_type"] = typ
                    verification_detail["expected_statuses"] = sorted(set(a["values"]))
                store.finding({"timestamp":time.time(),"check":"scenario_suite","title":f"Scenario assertion failed: {scenario['id']}",
                    "severity":scenario.get("severity","medium"),"confidence":"medium","scenario":scenario["id"],
                    "details":verification_detail,"evidence_id":obs.get("evidence_id"),"standards":scenario.get("category",[])})
            else:
                store.event({"type":"scenario_assertion_passed","scenario":scenario["id"],"details":detail})
        return {"scenario":scenario["id"],"results":results,"assertions":assertions,"failed_assertions":sum(1 for a in assertions if not a["passed"])}
    except Exception as exc:
        failure=exc
        store.finding({"timestamp":time.time(),"check":"scenario_suite","title":f"Scenario execution incomplete: {scenario['id']}",
                       "severity":"info","confidence":"low","scenario":scenario["id"],"details":{"error":type(exc).__name__}})
        return {"scenario":scenario["id"],"error":type(exc).__name__}
    finally:
        if stateful:
            for step in scenario.get("cleanup",[]):
                try:
                    p=expand(step); client.request(p.get("method","POST"),p["path"],auth=p.get("auth","default"),
                       headers=p.get("headers"),json_body=p.get("json"),body=p.get("body"),
                       reason=f"scenario:{scenario['id']}:cleanup:{p.get('name','cleanup')}")
                    store.event({"type":"scenario_cleanup_attempt","scenario":scenario["id"],"step":p.get("name"),"success":True})
                except Exception as cleanup_exc:
                    store.finding({"timestamp":time.time(),"check":"cleanup","title":f"Scenario cleanup failed: {scenario['id']}",
                                   "severity":"high","confidence":"high","scenario":scenario["id"],
                                   "details":{"error":type(cleanup_exc).__name__}})
