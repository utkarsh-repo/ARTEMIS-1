"""Loopback-only authenticated operator control API.

Credentials and roles are supplied by trusted server configuration, never by request
fields. This API is intentionally local-only: it has no TLS termination or remote
identity-provider integration and refuses non-loopback binds.
"""
from __future__ import annotations
import hmac
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .approval import ApprovalGateway
from .operations import runtime_health
from .runtime_store import RuntimeStore
from .evidence import SENSITIVE_FIELD_RE, redact_headers, redact_payload, redact_text, redact_url
import pathlib

MAX_BODY = 8192

_DASHBOARD_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARTEMIS Local Operations</title><style>
body{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#17202a;background:#f7f8fa}
main{background:white;border:1px solid #d9dee7;border-radius:12px;padding:1.25rem}h1{margin-top:0}label{display:block;margin:.75rem 0 .25rem}input,button{font:inherit;padding:.55rem;border:1px solid #aab4c3;border-radius:6px}input{max-width:100%;width:32rem}button{cursor:pointer;background:#edf2f7;margin:.3rem .3rem .3rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f4f7;padding:1rem;border-radius:8px}small{color:#4a5568}.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style></head><body><main><h1>ARTEMIS Operations</h1>
<p><small>Local operator dashboard. API authorization is enforced by the server; the page does not store the token.</small></p>
<label for="token">Bearer token</label><input id="token" type="password" autocomplete="off" spellcheck="false">
<button id="connect">Connect / refresh</button><p id="status" role="status">Not connected.</p>
<div class="grid"><section><h2>Health</h2><pre id="health">Not loaded</pre></section><section><h2>Jobs</h2><pre id="jobs">Not loaded</pre></section></div>
<div class="grid"><section><h2>Assessments</h2><pre id="assessments">Not loaded</pre></section><section><h2>Approvals</h2><pre id="approvals">Not loaded</pre></section></div>
<label for="assessmentid">Assessment ID</label><input id="assessmentid" autocomplete="off"><button id="assessmentdetails">Load assessment findings/assets/logs</button><pre id="assessmentdetail">Choose an assessment ID to inspect persisted results.</pre>
<label for="jobid">Job ID</label><input id="jobid" autocomplete="off"><button id="details">Load job details</button>
<pre id="detail">Choose a job ID to inspect task states.</pre>
<label for="cancelid">Cancel job ID (operator/admin role required)</label><input id="cancelid" autocomplete="off"><label for="reason">Reason</label><input id="reason" value="Cancelled from local dashboard"><button id="cancel">Cancel job</button>
<label for="approvalid">Approval ID</label><input id="approvalid" autocomplete="off"><label for="approvalreason">Approval reason</label><input id="approvalreason" value="Reviewed in local dashboard"><button id="approve">Approve (approver/admin)</button><button id="reject">Reject (approver/admin)</button><button id="revoke">Revoke (admin)</button><pre id="action">No action performed.</pre>
<script>
const el=id=>document.getElementById(id);let token='';
async function api(path,method='GET',body=null){const headers={'Authorization':'Bearer '+token};if(body!==null)headers['Content-Type']='application/json';const response=await fetch(path,{method,headers,body:body===null?undefined:JSON.stringify(body),cache:'no-store'});let data;try{data=await response.json()}catch{data={error:'invalid_json_response'}}if(!response.ok)throw new Error((data.error||'http_error')+' ('+response.status+')');return data}
async function refresh(){token=el('token').value.trim();if(!token){el('status').textContent='Enter the server-issued bearer token.';return}try{const [health,jobs,assessments,approvals]=await Promise.all([api('/health'),api('/jobs'),api('/assessments'),api('/approvals')]);el('health').textContent=JSON.stringify(health,null,2);el('jobs').textContent=JSON.stringify(jobs,null,2);el('assessments').textContent=JSON.stringify(assessments,null,2);el('approvals').textContent=JSON.stringify(approvals,null,2);el('status').textContent='Connected; data loaded from persisted runtime and assessment files.'}catch(e){el('status').textContent='Request failed: '+e.message}}
el('connect').addEventListener('click',refresh);el('assessmentdetails').addEventListener('click',async()=>{token=el('token').value.trim();try{el('assessmentdetail').textContent=JSON.stringify(await api('/assessments/'+encodeURIComponent(el('assessmentid').value.trim())),null,2)}catch(e){el('assessmentdetail').textContent='Request failed: '+e.message}});el('details').addEventListener('click',async()=>{token=el('token').value.trim();try{el('detail').textContent=JSON.stringify(await api('/jobs/'+encodeURIComponent(el('jobid').value.trim())),null,2)}catch(e){el('detail').textContent='Request failed: '+e.message}});el('cancel').addEventListener('click',async()=>{token=el('token').value.trim();try{const result=await api('/jobs/'+encodeURIComponent(el('cancelid').value.trim())+'/cancel','POST',{reason:el('reason').value});el('action').textContent=JSON.stringify(result,null,2);await refresh()}catch(e){el('action').textContent='Request failed: '+e.message}});
async function approvalAction(action,approve){token=el('token').value.trim();const id=encodeURIComponent(el('approvalid').value.trim());try{let result;if(action==='decision')result=await api('/approvals/'+id+'/decision','POST',{approve,reason:el('approvalreason').value});else result=await api('/approvals/'+id+'/revoke','POST',{reason:el('approvalreason').value});el('action').textContent=JSON.stringify(result,null,2);await refresh()}catch(e){el('action').textContent='Request failed: '+e.message}}
el('approve').addEventListener('click',()=>approvalAction('decision',true));el('reject').addEventListener('click',()=>approvalAction('decision',false));el('revoke').addEventListener('click',()=>approvalAction('revoke',false));
</script></main></body></html>'''


def _safe_api_value(value, key=""):
    low = key.lower()
    if low in {"authorization", "cookie", "set-cookie", "token", "secret", "password", "api_key", "access_token"} or SENSITIVE_FIELD_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _safe_api_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_api_value(item, key) for item in value]
    if isinstance(value, str):
        if low in {"url", "target", "base_url"} or value.startswith(("http://", "https://")):
            return redact_url(value)[:4096]
        return redact_text(value)[:2000]
    return value


def _read_jsonl_tail(path, *, limit=200, max_bytes=5 * 1024 * 1024):
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("assessment evidence file is unsafe or exceeds the read limit")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        if len(line) > 200_000:
            raise ValueError("assessment evidence row exceeds the read limit")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("assessment evidence contains malformed JSON") from exc
        rows.append(_safe_api_value(value))
    return rows


class OperatorControlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, *, runtime_db, credentials, policy=None, run_root=None):
        host, _ = address
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("operator API is loopback-only; remote bind is unsupported")
        if not isinstance(credentials, dict) or not credentials:
            raise ValueError("server-side credential map is required")
        self.runtime_db = runtime_db
        self.run_root = pathlib.Path(run_root if run_root is not None else pathlib.Path(runtime_db).parent).resolve()
        self.credentials = {}
        for token, identity in credentials.items():
            if not isinstance(token, str) or len(token) < 24 or not isinstance(identity, dict):
                raise ValueError("each API token must be at least 24 characters with server-side identity metadata")
            operator_id, role = identity.get("operator_id"), identity.get("role")
            if not isinstance(operator_id, str) or not operator_id or role not in {"viewer", "operator", "approver", "admin"}:
                raise ValueError("credential identity must define operator_id and a supported role")
            self.credentials[token] = {"operator_id": operator_id, "role": role}
        self.policy = policy
        super().__init__(address, _make_handler())


def _make_handler():
    class Handler(BaseHTTPRequestHandler):
        server_version = "ARTEMIS-Operator/1"

        def log_message(self, fmt, *args):
            # Do not log Authorization headers, request bodies, or query strings.
            return

        def _json(self, status, body):
            payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _identity(self, minimum_role="viewer"):
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                self._json(401, {"error": "authentication_required"}); return None
            supplied = header[7:]
            identity = None
            # Constant-time compare each configured secret; no role/identity is accepted from client input.
            for token, record in self.server.credentials.items():
                if hmac.compare_digest(supplied, token): identity = record
            if identity is None:
                self._json(401, {"error": "invalid_credentials"}); return None
            permitted = {
                "viewer": {"viewer", "operator", "approver", "admin"},
                "operator": {"operator", "admin"},
                "approver": {"approver", "admin"},
                "admin": {"admin"},
            }
            if identity["role"] not in permitted[minimum_role]:
                self._json(403, {"error": "insufficient_role"}); return None
            return identity

        def _body(self):
            try: length = int(self.headers.get("Content-Length", "0"))
            except ValueError: raise ValueError("invalid_content_length")
            if length < 0 or length > MAX_BODY: raise ValueError("request_body_too_large")
            raw = self.rfile.read(length) if length else b"{}"
            value = json.loads(raw)
            if not isinstance(value, dict): raise ValueError("request_body_must_be_object")
            return value

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                payload = _DASHBOARD_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
                return
            identity = self._identity("viewer")
            if identity is None: return
            if path == "/health":
                self._json(200, runtime_health(self.server.runtime_db)); return
            if path == "/jobs":
                try: jobs = RuntimeStore(self.server.runtime_db).list_jobs(limit=100)
                except Exception as exc: self._json(500, {"error": type(exc).__name__}); return
                self._json(200, {"jobs": jobs}); return
            if path == "/approvals":
                try:
                    approvals = RuntimeStore(self.server.runtime_db).list_approvals(limit=100)
                    for approval in approvals:
                        approval["target"] = redact_url(approval.get("target", ""))[:4096]
                        approval.pop("parameter_keys", None)
                except Exception as exc: self._json(500, {"error": type(exc).__name__}); return
                self._json(200, {"approvals": approvals}); return
            if path == "/assessments":
                try:
                    assessments = []
                    if self.server.run_root.exists():
                        for child in sorted(self.server.run_root.iterdir(), key=lambda item: item.name, reverse=True):
                            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", child.name) or child.is_symlink() or not child.is_dir():
                                continue
                            summary_path = child / "run_summary.json"
                            board_path = child / "blackboard.json"
                            if not summary_path.is_file() and not board_path.is_file():
                                continue
                            summary = {}
                            if summary_path.is_file() and not summary_path.is_symlink() and summary_path.stat().st_size <= 1_000_000:
                                try: summary = json.loads(summary_path.read_text(encoding="utf-8"))
                                except (json.JSONDecodeError, OSError): summary = {}
                            assessments.append({"id": child.name, "status": summary.get("status", "available"),
                                               "target": redact_url(str(summary.get("target", "")))[:4096],
                                               "provider": str(summary.get("provider", "unknown"))[:100],
                                               "requests_used": summary.get("requests_used"),
                                               "findings_count": summary.get("findings_count"),
                                               "finished_at": summary.get("finished_at")})
                            if len(assessments) >= 100: break
                except Exception as exc: self._json(500, {"error": type(exc).__name__}); return
                self._json(200, {"assessments": assessments}); return
            assessment_match = re.fullmatch(r"/assessments/([A-Za-z0-9_.-]{1,100})", path)
            if assessment_match:
                assessment_id = assessment_match.group(1)
                root = self.server.run_root
                candidate = root / assessment_id
                try:
                    resolved = candidate.resolve(strict=True)
                    if candidate.is_symlink() or resolved.parent != root or not resolved.is_dir():
                        raise ValueError("unsafe assessment path")
                    board_path = resolved / "blackboard.json"
                    if board_path.exists() and (board_path.is_symlink() or board_path.stat().st_size > 5 * 1024 * 1024):
                        raise ValueError("blackboard file is unsafe or too large")
                    board = json.loads(board_path.read_text(encoding="utf-8")) if board_path.is_file() else {}
                    summary_path = resolved / "run_summary.json"
                    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() and not summary_path.is_symlink() and summary_path.stat().st_size <= 1_000_000 else {}
                    findings = _read_jsonl_tail(resolved / "findings.jsonl")
                    events = _read_jsonl_tail(resolved / "events.jsonl")
                    traffic = _read_jsonl_tail(resolved / "traffic.jsonl")
                    safe_findings = [{key: _safe_api_value(row.get(key), key) for key in ("finding_id", "title", "severity", "confidence", "check", "url", "evidence_id", "traffic_ids", "standards", "timestamp", "details")} for row in findings]
                    safe_assets = [_safe_api_value(item) for item in board.get("assets", [])[:500]] if isinstance(board, dict) and isinstance(board.get("assets", []), list) else []
                    safe_claims = [_safe_api_value(item) for item in board.get("claims", [])[:500]] if isinstance(board, dict) and isinstance(board.get("claims", []), list) else []
                    self._json(200, {"assessment": {"id": assessment_id, "summary": _safe_api_value(summary),
                                                       "test_statuses": _safe_api_value(board.get("test_statuses", {})) if isinstance(board, dict) else {}},
                                     "assets": safe_assets, "claims": safe_claims, "findings": safe_findings,
                                     "events": events, "traffic": traffic})
                except FileNotFoundError:
                    self._json(404, {"error": "assessment_not_found"})
                except (ValueError, OSError, json.JSONDecodeError) as exc:
                    self._json(409, {"error": type(exc).__name__})
                return
            match = re.fullmatch(r"/jobs/([A-Za-z0-9_-]{1,128})", path)
            if match:
                store = RuntimeStore(self.server.runtime_db)
                job = store.get_job(match.group(1))
                if job is None: self._json(404, {"error": "job_not_found"}); return
                safe_job = {key: job.get(key) for key in ("id", "status", "policy_digest", "created_at", "updated_at", "cancelled_at")}
                safe_tasks = []
                for task in store.list_tasks(job["id"]):
                    safe_tasks.append({key: task.get(key) for key in ("id", "task_key", "task_type", "status", "priority", "attempts", "max_attempts", "worker_id", "lease_expires_at", "created_at", "updated_at", "started_at", "finished_at", "error")})
                self._json(200, {"job": safe_job, "tasks": safe_tasks})
                return
            self._json(404, {"error": "not_found"})

        def do_POST(self):
            path = urlparse(self.path).path
            cancel_match = re.fullmatch(r"/jobs/([A-Za-z0-9_-]{1,128})/cancel", path)
            decide_match = re.fullmatch(r"/approvals/([A-Za-z0-9_-]{1,128})/decision", path)
            revoke_match = re.fullmatch(r"/approvals/([A-Za-z0-9_-]{1,128})/revoke", path)
            if cancel_match:
                identity = self._identity("operator")
                if identity is None: return
                try: body = self._body()
                except (ValueError, json.JSONDecodeError) as exc: self._json(400, {"error": str(exc)}); return
                reason = str(body.get("reason", "operator API cancellation"))[:500]
                try: result = RuntimeStore(self.server.runtime_db).cancel_job(cancel_match.group(1), reason=reason)
                except Exception as exc: self._json(409, {"error": type(exc).__name__}); return
                self._json(200, {"job": result, "operator_id": identity["operator_id"]}); return
            if decide_match:
                identity = self._identity("approver")
                if identity is None: return
                try: body = self._body()
                except (ValueError, json.JSONDecodeError) as exc: self._json(400, {"error": str(exc)}); return
                if not isinstance(body.get("approve"), bool): self._json(400, {"error": "approve_boolean_required"}); return
                try:
                    result = ApprovalGateway(RuntimeStore(self.server.runtime_db), self.server.policy).decide(
                        decide_match.group(1), approver_id=identity["operator_id"], approve=body["approve"],
                        reason=str(body.get("reason", ""))[:500])
                except Exception as exc: self._json(409, {"error": type(exc).__name__}); return
                self._json(200, result); return
            if revoke_match:
                identity = self._identity("admin")
                if identity is None: return
                try: body = self._body()
                except (ValueError, json.JSONDecodeError) as exc: self._json(400, {"error": str(exc)}); return
                try:
                    result = ApprovalGateway(RuntimeStore(self.server.runtime_db), self.server.policy).revoke(
                        revoke_match.group(1), revoked_by=identity["operator_id"],
                        reason=str(body.get("reason", "operator API revocation"))[:500])
                except Exception as exc: self._json(409, {"error": type(exc).__name__}); return
                self._json(200, result); return
            self._json(404, {"error": "not_found"})
    return Handler
