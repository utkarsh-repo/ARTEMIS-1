from __future__ import annotations
import json, time
from pathlib import Path
from urllib.parse import urljoin
from .policy import validate_url, PolicyError

def inventory(path, policy, store, client=None):
    if not path: return {"paths":[],"operations":0}
    spec=json.loads(Path(path).read_text(encoding="utf-8"))
    paths=spec.get("paths",{})
    rows=[]; operations=0
    for route, item in paths.items():
        if not isinstance(item,dict): continue
        for method,operation in item.items():
            m=method.upper()
            if m not in ("GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"): continue
            operations+=1
            full=urljoin(policy["base_url"].rstrip("/")+"/",route.lstrip("/"))
            row={"path":route,"method":m,"operation_id":operation.get("operationId") if isinstance(operation,dict) else None,
                 "tags":operation.get("tags",[]) if isinstance(operation,dict) else [],"probe_status":"inventory_only"}
            try:
                # Template paths cannot safely be requested without concrete lab fixture IDs.
                if "{" in route or "}" in route:
                    raise PolicyError("Template path needs explicit fixture binding")
                validate_url(policy,full,m,resolve_dns=False)
                row["in_scope"]=True
                if client and policy.get("probe_openapi_gets",False) and m in ("GET","HEAD","OPTIONS"):
                    result=client.request(m,full,auth="default",reason="openapi_inventory")
                    row["probe_status"]=result.get("status","transport_error")
                    row["evidence_id"]=result.get("evidence_id")
            except PolicyError as exc:
                row["in_scope"]=False; row["skip_reason"]=str(exc)
            rows.append(row)
    summary={"title":spec.get("info",{}).get("title"),"version":spec.get("info",{}).get("version"),
             "path_count":len(paths),"operation_count":operations,"operations":rows,"generated_at":time.time()}
    store.append("api_inventory.json",summary)
    store.event({"type":"openapi_inventory","paths":len(paths),"operations":operations})
    return summary
