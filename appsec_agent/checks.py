from __future__ import annotations
import json, time
from urllib.parse import urlparse
from .evidence import safe_observation, redact_text

def _finding(store,test_id,title,severity,obs,details,confidence="medium",standards=None):
    store.finding({"timestamp":time.time(),"check":test_id,"title":title,"severity":severity,"confidence":confidence,
                   "url":obs.get("url") if isinstance(obs,dict) else None,"details":details,
                   "evidence_id":obs.get("evidence_id") if isinstance(obs,dict) else None,"standards":standards or []})

def analyze_headers(obs, policy, store):
    h={k.lower():v for k,v in obs.get("_raw_headers",obs.get("headers",{})).items()}
    missing=[x for x in policy.get("security_headers",[]) if x.lower() not in h]
    if missing: _finding(store,"security_headers","Security headers missing","low",obs,{"missing":missing},standards=["A02:2025","API8:2023"])
    else: store.event({"type":"check_pass","check":"security_headers","url":obs.get("url")})

def analyze_cookies(obs, store):
    headers=obs.get("_raw_headers",{})
    cookies=[v for k,v in headers.items() if k.lower()=="set-cookie"]
    for cookie in cookies:
        pieces=[x.strip() for x in cookie.split(";")]
        attrs={x.split("=",1)[0].lower() for x in pieces[1:]}
        missing=[x for x in ("secure","httponly","samesite") if x not in attrs]
        if missing: _finding(store,"cookie_flags","Cookie missing security attributes","low",obs,{"missing_attributes":missing},standards=["A02:2025","A04:2025"])
    if not cookies: store.event({"type":"check_observation","check":"cookie_flags","url":obs.get("url"),"message":"No Set-Cookie header observed on this response."})

def analyze_disclosure(obs,store):
    h={k.lower():v for k,v in obs.get("_raw_headers",obs.get("headers",{})).items()}
    details={k:h[k] for k in ("server","x-powered-by","x-aspnet-version") if k in h}
    if details: _finding(store,"technology_disclosure","Technology disclosure headers present","info",obs,details,standards=["A02:2025","CWE-200"])
    else: store.event({"type":"check_pass","check":"technology_disclosure","url":obs.get("url")})

def analyze_cache(obs,store):
    h={k.lower():v for k,v in obs.get("_raw_headers",obs.get("headers",{})).items()}
    cc=h.get("cache-control","")
    path=urlparse(obs.get("url","")).path.lower()
    sensitive=any(w in path for w in ("profile","account","payment","order","user","token","session"))
    if sensitive and not any(x in cc.lower() for x in ("no-store","private")):
        _finding(store,"cache_policy","Potentially sensitive path lacks restrictive Cache-Control","low",obs,{"cache_control":cc or None,"path":path},standards=["A04:2025","CWE-200"])
    else: store.event({"type":"check_observation","check":"cache_policy","url":obs.get("url"),"cache_control":cc})

def analyze_content_type(obs,policy,store):
    h={k.lower():v for k,v in obs.get("_raw_headers",obs.get("headers",{})).items()}
    ct=h.get("content-type","")
    if ct and ("text/html" in ct.lower() or "application/xhtml" in ct.lower()) and "x-content-type-options" not in h:
        _finding(store,"content_type","HTML response does not set X-Content-Type-Options","low",obs,{"content_type":ct},standards=["A02:2025"])
    if not ct and obs.get("status",0)<400:
        _finding(store,"content_type","Successful response has no Content-Type","info",obs,{},confidence="low")
    else: store.event({"type":"check_observation","check":"content_type","url":obs.get("url"),"content_type":ct})

def analyze_error(obs,store):
    status=obs.get("status",0)
    if status>=500:
        excerpt=obs.get("_body_text","")[:800]
        markers=[x for x in ("Traceback","stack trace","SQLException","Exception in thread"," at /var/","/home/") if x.lower() in excerpt.lower()]
        _finding(store,"error_surface","Server error response observed","medium",obs,{"status":status,"diagnostic_markers":markers,"excerpt":redact_text(excerpt[:250])},confidence="low",standards=["A10:2025","CWE-200"])
    else: store.event({"type":"check_observation","check":"error_surface","url":obs.get("url"),"status":status})

def run_cors(client, target, store):
    obs=client.request("OPTIONS",target,auth="anonymous",
        headers={"Origin":"https://appsec-probe.invalid","Access-Control-Request-Method":"GET","Access-Control-Request-Headers":"authorization,content-type"},
        reason="check:cors_preflight")
    h={k.lower():v for k,v in obs.get("_raw_headers",obs.get("headers",{})).items()}
    origin=h.get("access-control-allow-origin","")
    creds=h.get("access-control-allow-credentials","").lower()=="true"
    if origin=="*" and creds:
        _finding(store,"cors_preflight","Wildcard CORS origin combined with credentials","high",obs,{"allow_origin":origin,"allow_credentials":True},confidence="medium",standards=["A02:2025","API8:2023"])
    elif origin=="https://appsec-probe.invalid" and creds:
        _finding(store,"cors_preflight","Arbitrary CORS origin appears reflected with credentials","medium",obs,{"allow_origin":origin,"allow_credentials":True},confidence="low",standards=["A02:2025","API8:2023"])
    else: store.event({"type":"check_observation","check":"cors_preflight","url":target,"allow_origin":origin or None,"allow_credentials":creds})
    return obs

def run_method_surface(client,target,store):
    obs=client.request("OPTIONS",target,auth="anonymous",reason="check:http_method_surface")
    h={k.lower():v for k,v in obs.get("_raw_headers",obs.get("headers",{})).items()}
    allow=h.get("allow","")
    methods={x.strip().upper() for x in allow.split(",")}
    suspicious=methods.intersection({"TRACE","CONNECT"})
    if suspicious:
        _finding(store,"http_method_surface","Potentially risky HTTP methods advertised","low",obs,{"allow":allow,"methods":sorted(suspicious)},standards=["A02:2025"])
    else: store.event({"type":"check_observation","check":"http_method_surface","url":target,"allow":allow or None})
    return obs

def analyze_anonymous_boundary(client, paths, store):
    for path in paths:
        obs=client.request("GET",path,auth="anonymous",reason="check:anonymous_auth_boundary")
        if obs.get("status") not in (401,403):
            _finding(store,"anonymous_auth_boundary","Configured protected path did not return 401/403 anonymously","medium",obs,
                     {"status":obs.get("status"),"expected":[401,403],"path":path},confidence="low",standards=["A01:2025","A07:2025","API2:2023","CWE-306"])
        else: store.event({"type":"check_observation","check":"anonymous_auth_boundary","url":obs.get("url"),"status":obs.get("status")})
        if client.server_errors>=int(client.policy.get("stop_on_5xx",3)): break

def safe_public_observation(obs):
    return safe_observation(obs)
