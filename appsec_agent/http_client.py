from __future__ import annotations
import os, time
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from requests.utils import select_proxy
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.util.connection import create_connection
from urllib3.exceptions import NewConnectionError
from .policy import validate_url, resolve_target_ips, PolicyError
from .authorization import InlineRequestAuthorizationGateway, AuthorizationDenied

class RequestBudgetExceeded(RuntimeError): pass


class _PinnedConnectionMixin:
    """Mixin that dials a validated IP while retaining the URL host for Host/SNI."""
    def __init__(self, *args, pinned_ip=None, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        if not self.pinned_ip:
            return super()._new_conn()
        try:
            return create_connection((self.pinned_ip, self.port), self.timeout,
                                     source_address=self.source_address,
                                     socket_options=self.socket_options)
        except OSError as exc:
            raise NewConnectionError(self, f"Failed pinned connection to {self.pinned_ip}: {exc}") from exc


class _PinnedHTTPConnection(_PinnedConnectionMixin, HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, HTTPSConnection):
    pass

class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedAddressAdapter(HTTPAdapter):
    """Disable proxy-based bypasses and pin each connection to a just-validated IP."""
    def __init__(self, policy):
        self.policy = policy
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        if select_proxy(request.url, proxies):
            raise PolicyError("Proxy connections are disabled because they bypass destination IP pinning")
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        ips = resolve_target_ips(self.policy, request.url)
        pinned_ip = ips[0]
        pool_kwargs["pinned_ip"] = pinned_ip
        scheme = host_params["scheme"]
        if scheme == "https":
            return _PinnedHTTPSConnectionPool(host=host_params["host"], port=host_params["port"], **pool_kwargs)
        if scheme == "http":
            pool_kwargs.pop("cert_reqs", None)
            return _PinnedHTTPConnectionPool(host=host_params["host"], port=host_params["port"], **pool_kwargs)
        raise PolicyError("Only HTTP(S) connections are supported")

class LabHTTPClient:
    def __init__(self, policy, evidence, *, assessment_id="legacy-inline", authorization_gateway=None):
        self.policy=policy; self.evidence=evidence; self.used=0; self.last=0.0; self.server_errors=0
        self.sessions={}
        self.base_url=policy["base_url"].rstrip("/")+"/"
        self.authorization_gateway = authorization_gateway or InlineRequestAuthorizationGateway(
            policy, assessment_id=assessment_id,
            audit=lambda event: evidence.event({"type": "execution_authorization", **event}))
    def _session(self, auth="default"):
        if auth not in self.sessions:
            s=requests.Session(); s.trust_env=False
            pinned_adapter = _PinnedAddressAdapter(self.policy)
            s.mount("http://", pinned_adapter)
            s.mount("https://", pinned_adapter)
            s.headers.update({"User-Agent":self.policy.get("user_agent","AutonomousLabAppSecAgent/2.0"),"Accept":"*/*"})
            if auth=="default":
                env=self.policy.get("auth_env","LAB_BEARER_TOKEN")
                token=os.environ.get(env)
                cookie=os.environ.get("LAB_COOKIE")
                if token: s.headers["Authorization"]="Bearer "+token
                if cookie: s.headers["Cookie"]=cookie
            elif auth not in ("anonymous",None):
                if not auth.startswith(("LAB_TOKEN_","LAB_COOKIE_")):
                    raise PolicyError("Scenario auth must be anonymous or a LAB_TOKEN_/LAB_COOKIE_ environment variable")
                value=os.environ.get(auth)
                if not value: raise PolicyError(f"Credential environment variable {auth} is not set")
                if auth.startswith("LAB_TOKEN_"): s.headers["Authorization"]="Bearer "+value
                else: s.headers["Cookie"]=value
            self.sessions[auth]=s
        return self.sessions[auth]
    def request(self, method, path_or_url, *, auth="default", headers=None, json_body=None, body=None, reason="test"):
        method=method.upper()
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url=path_or_url
        else:
            url=urljoin(self.base_url,path_or_url.lstrip("/"))
        if auth is not None and (not isinstance(auth, str) or auth not in ("default", "anonymous")
                                 and not __import__("re").fullmatch(r"LAB_(?:TOKEN|COOKIE)_[A-Z0-9_]{1,64}", auth)):
            raise PolicyError("Scenario auth must be default, anonymous, None or a valid LAB_TOKEN_/LAB_COOKIE_ environment variable")
        try:
            authorization = self.authorization_gateway.authorize_request(
                url, method, headers=headers, has_body=(json_body is not None or body is not None),
                auth_profile=auth)
        except AuthorizationDenied as exc:
            raise PolicyError("request denied by execution authorization gateway") from exc
        # Defense in depth: retain the transport's independent URL/scope gate;
        # the adapter performs fresh DNS/IP validation and pins the socket.
        validate_url(self.policy,url,method)
        if authorization.get("policy_digest") != self.authorization_gateway.policy_digest or authorization.get("auth_profile") != auth:
            raise PolicyError("request authorization snapshot no longer matches the requested action")
        if self.used>=int(self.policy["max_requests"]):
            raise RequestBudgetExceeded("max_requests exhausted")
        delay=1/max(0.1,float(self.policy.get("requests_per_second",1.0)))
        wait=delay-(time.monotonic()-self.last)
        if wait>0: time.sleep(wait)
        self.last=time.monotonic(); self.used+=1
        session=self._session(auth)
        if auth == "anonymous":
            session.cookies.clear()
        req_headers=dict(session.headers)
        if headers: req_headers.update(headers)
        start=time.monotonic()
        try:
            response=session.request(method,url,headers=headers,json=json_body,data=body,timeout=float(self.policy.get("request_timeout_seconds",12)),
                                     allow_redirects=False,stream=True,verify=True)
            chunks=[]; total=0; cap=int(self.policy.get("max_response_bytes",250000))
            for chunk in response.iter_content(8192):
                if not chunk: continue
                take=chunk[:max(0,cap-total)]
                chunks.append(take); total+=len(take)
                if total>=cap: break
            response_body=b"".join(chunks)
            # Always release the response, including when the body cap stops reading early.
            response.close()
            elapsed=round((time.monotonic()-start)*1000,2)
            evidence_headers=dict(req_headers)
            if headers: evidence_headers.update(headers)
            request_record={"method":method,"url":url,"headers":evidence_headers,"json":json_body,"body":body}
            evidence_id=self.evidence.capture(request_record,response.status_code,dict(response.headers),response_body,elapsed,reason)
            if response.status_code>=500: self.server_errors+=1
            text=response_body.decode(response.encoding or "utf-8",errors="replace")
            traffic_id = self.evidence.traffic_id_for(evidence_id)
            obs={"url":url,"method":method,"status":response.status_code,"headers":dict(response.headers),
                 "content_type":response.headers.get("Content-Type",""),"body_excerpt":text[:int(self.policy.get("max_model_observation_chars",3000))],
                 "body_sha256":__import__("hashlib").sha256(response_body).hexdigest(),"elapsed_ms":elapsed,
                 "truncated":total>=cap,"evidence_id":evidence_id,"traffic_id":traffic_id,
                 "_raw_headers":dict(response.headers),"_raw_body":response_body,"_body_text":text}
            self.evidence.event({"type":"http_response","status":response.status_code,"url":url,"method":method,
                                 "evidence_id":evidence_id,"traffic_id":traffic_id,"elapsed_ms":elapsed})
            return obs
        except requests.RequestException as exc:
            elapsed=round((time.monotonic()-start)*1000,2)
            evidence_id = self.evidence.capture_transport_error(
                {"method":method,"url":url,"headers":req_headers,"json":json_body,"body":body},
                type(exc).__name__, elapsed, reason)
            traffic_id = self.evidence.traffic_id_for(evidence_id)
            self.evidence.event({"type":"transport_error","url":url,"error":type(exc).__name__,
                                 "evidence_id":evidence_id,"traffic_id":traffic_id})
            return {"url":url,"method":method,"transport_error":type(exc).__name__,
                    "evidence_id":evidence_id,"traffic_id":traffic_id}
