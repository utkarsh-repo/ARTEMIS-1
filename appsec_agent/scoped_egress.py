"""Fail-closed destination authorization and a minimal CONNECT egress broker.

This is a *component*, not a complete host-network security boundary. A worker
must be unable to route packets except to this broker (for example through a
separately tested Linux nftables/namespace policy). HTTPS CONNECT can enforce
host/port/IP but cannot inspect encrypted paths; clients must disable redirects
or re-authorize each redirect URL through the normal HTTP policy gate.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import logging
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from .policy import PolicyError

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    assessment_id: str
    policy_digest: str
    host: str
    port: int
    addresses: tuple[str, ...] = ()
    reason: str = "allowed"
    signature: str = ""
    issued_at: float = 0.0


class ScopedEgressPolicy:
    """Exact-host/port egress policy with all-answer DNS validation.

    `allowed_private_cidrs` is an explicit exception list, never a global
    allow-private switch. Every DNS answer must be globally routable or match
    one of those explicit CIDRs; mixed public/private answers are denied.
    """

    def __init__(self, *, assessment_id: str, policy_digest: str,
                 allowed_hosts: Iterable[str], allowed_ports: Iterable[int] = (443,),
                 allowed_private_cidrs: Iterable[str] = (),
                 resolver: Callable = socket.getaddrinfo,
                 audit: Callable[[dict], None] | None = None):
        if not assessment_id or not policy_digest:
            raise ValueError("assessment_id and policy_digest are required")
        hosts = tuple(allowed_hosts)
        if not hosts or any(not isinstance(h, str) or not h or h != h.lower() or h.endswith(".") or "*" in h
                            or not h.isascii() or any(ch.isspace() for ch in h) or ":" in h or "@" in h for h in hosts):
            raise ValueError("allowed_hosts must contain exact lowercase ASCII hostnames")
        ports = tuple(allowed_ports)
        if not ports or any(not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535 for p in ports):
            raise ValueError("allowed_ports must contain valid integer ports")
        try:
            private = tuple(ipaddress.ip_network(x, strict=True) for x in allowed_private_cidrs)
        except ValueError as exc:
            raise ValueError("allowed_private_cidrs contains an invalid CIDR") from exc
        self.assessment_id = assessment_id
        self.policy_digest = policy_digest
        self.allowed_hosts = frozenset(hosts)
        self.allowed_ports = frozenset(ports)
        self.allowed_private_cidrs = private
        self.resolver = resolver
        self.audit = audit or (lambda event: _LOG.info("egress_decision %s", json.dumps(event, sort_keys=True)))
        self._decision_key = secrets.token_bytes(32)

    def _signature(self, decision: EgressDecision) -> str:
        material = json.dumps({"assessment_id": decision.assessment_id, "policy_digest": decision.policy_digest,
            "host": decision.host, "port": decision.port, "addresses": list(decision.addresses),
            "issued_at": decision.issued_at},
            sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._decision_key, material, hashlib.sha256).hexdigest()

    def _record(self, decision: EgressDecision) -> EgressDecision:
        if decision.allowed:
            decision = replace(decision, issued_at=time.time(), signature="")
            decision = replace(decision, signature=self._signature(decision))
        self.audit({"event": "egress_allow" if decision.allowed else "egress_deny",
                    "assessment_id": decision.assessment_id, "policy_digest": decision.policy_digest,
                    "host": decision.host, "port": decision.port,
                    "addresses": list(decision.addresses), "reason": decision.reason,
                    "timestamp": time.time()})
        return decision

    def authorize(self, host: str, port: int, *, assessment_id: str,
                  policy_digest: str) -> EgressDecision:
        if not isinstance(host, str) or not host or host.endswith(".") or not host.isascii():
            return self._record(EgressDecision(False, assessment_id, policy_digest, "<invalid-host>", port, reason="ambiguous_host"))
        normalized = host.lower()
        if assessment_id != self.assessment_id or policy_digest != self.policy_digest:
            return self._record(EgressDecision(False, assessment_id, policy_digest, normalized, port, reason="stale_assessment_or_policy"))
        if normalized not in self.allowed_hosts:
            return self._record(EgressDecision(False, assessment_id, policy_digest, normalized, port, reason="host_not_allowlisted"))
        if not isinstance(port, int) or isinstance(port, bool) or port not in self.allowed_ports:
            return self._record(EgressDecision(False, assessment_id, policy_digest, normalized, port if isinstance(port, int) else -1, reason="port_not_allowlisted"))
        try:
            infos = self.resolver(normalized, port, type=socket.SOCK_STREAM)
            answers = []
            for info in infos:
                raw = info[4][0]
                address = ipaddress.ip_address(raw.split("%", 1)[0])
                explicitly_allowed = any(address.version == net.version and address in net for net in self.allowed_private_cidrs)
                if address.is_unspecified or address.is_multicast or address.is_reserved or address.is_link_local:
                    raise PolicyError("DNS answer is unspecified, multicast, reserved or link-local")
                if address.is_loopback and not explicitly_allowed:
                    raise PolicyError("loopback DNS answer is prohibited without an explicit lab CIDR")
                if not address.is_global and not explicitly_allowed:
                    raise PolicyError("DNS answer is not globally routable")
                answers.append(str(address))
            unique = tuple(dict.fromkeys(answers))
            if not unique:
                raise PolicyError("DNS returned no addresses")
            decision = EgressDecision(True, assessment_id, policy_digest, normalized, port, unique)
        except (OSError, ValueError, IndexError, TypeError, PolicyError) as exc:
            decision = EgressDecision(False, assessment_id, policy_digest, normalized, port, reason=type(exc).__name__ + ":" + str(exc)[:120])
        return self._record(decision)

    def connect_pinned(self, decision: EgressDecision, *, timeout: float = 5.0) -> socket.socket:
        """Connect only to an address from this exact allowed decision; never re-resolve."""
        if (not decision.allowed or decision.assessment_id != self.assessment_id
                or decision.policy_digest != self.policy_digest or not decision.addresses
                or decision.issued_at <= 0 or time.time() - decision.issued_at > 5.0
                or not hmac.compare_digest(decision.signature, self._signature(decision))):
            raise PolicyError("egress decision is invalid or stale")
        last_error = None
        for raw in decision.addresses:
            ip = ipaddress.ip_address(raw)
            sock = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((str(ip), decision.port))
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        raise PolicyError("could not connect to any previously authorized pinned address") from last_error


class ScopedConnectProxy:
    """Small HTTP CONNECT broker; host/port and resolved IPs are checked per tunnel.

    The caller is responsible for network isolation that makes this the only
    route from workers. It deliberately refuses plain HTTP proxy requests.
    """
    def __init__(self, policy: ScopedEgressPolicy, *, assessment_id: str, policy_digest: str,
                 current_context: Callable[[], tuple[str, str]],
                 bind: tuple[str, int] = ("127.0.0.1", 0), connect_timeout: float = 5.0):
        if not callable(current_context):
            raise ValueError("current_context callback is required for live assessment/policy revalidation")
        self.policy = policy
        self.assessment_id = assessment_id
        self.policy_digest = policy_digest
        self.current_context = current_context
        self.connect_timeout = connect_timeout
        policy_ref = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                client = self.request
                client.settimeout(3.0)
                try:
                    raw = bytearray()
                    while b"\r\n\r\n" not in raw and len(raw) <= 8192:
                        chunk = client.recv(1024)
                        if not chunk:
                            return
                        raw.extend(chunk)
                    if len(raw) > 8192:
                        return self.deny("request_too_large")
                    header_end = bytes(raw).find(b"\r\n\r\n") + 4
                    initial_tunnel_data = bytes(raw[header_end:])
                    first = bytes(raw).split(b"\r\n", 1)[0].decode("ascii", "strict").split()
                    if len(first) != 3 or first[0] != "CONNECT" or first[2] not in {"HTTP/1.0", "HTTP/1.1"}:
                        return self.deny("only_connect_supported")
                    authority = first[1]
                    if authority.startswith("[") and "]:" in authority:
                        host, port_text = authority[1:].split("]:", 1)
                    elif authority.count(":") == 1:
                        host, port_text = authority.rsplit(":", 1)
                    else:
                        return self.deny("malformed_authority")
                    if not port_text.isdigit():
                        return self.deny("malformed_port")
                    port = int(port_text)
                    try:
                        current_assessment, current_digest = policy_ref.current_context()
                    except Exception:
                        return self.deny("current_policy_unavailable")
                    if current_assessment != policy_ref.assessment_id or current_digest != policy_ref.policy_digest:
                        return self.deny("stale_assessment_or_policy")
                    decision = policy_ref.policy.authorize(host, port, assessment_id=current_assessment,
                                                           policy_digest=current_digest)
                    if not decision.allowed:
                        return self.deny(decision.reason)
                    # Recheck trusted live state immediately before dialing the
                    # already-authorized pinned IP to minimize policy-change races.
                    try:
                        latest_assessment, latest_digest = policy_ref.current_context()
                    except Exception:
                        return self.deny("current_policy_unavailable")
                    if latest_assessment != decision.assessment_id or latest_digest != decision.policy_digest:
                        return self.deny("stale_assessment_or_policy")
                    upstream = policy_ref.policy.connect_pinned(decision, timeout=policy_ref.connect_timeout)
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self.tunnel(client, upstream, initial_tunnel_data)
                except (OSError, UnicodeError, ValueError, IndexError, PolicyError):
                    try:
                        client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    except OSError:
                        pass

            def deny(self, reason):
                policy_ref.policy.audit({"event": "egress_deny", "assessment_id": policy_ref.assessment_id,
                    "policy_digest": policy_ref.policy_digest, "reason": reason, "timestamp": time.time()})
                try:
                    self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass

            @staticmethod
            def tunnel(left, right, initial_client_data=b""):
                import selectors
                left.settimeout(None); right.settimeout(None)
                if initial_client_data:
                    right.sendall(initial_client_data)
                selector = selectors.DefaultSelector()
                selector.register(left, selectors.EVENT_READ, right)
                selector.register(right, selectors.EVENT_READ, left)
                try:
                    while True:
                        for key, _ in selector.select(timeout=30):
                            data = key.fileobj.recv(65536)
                            if not data:
                                return
                            key.data.sendall(data)
                finally:
                    selector.close(); right.close()

        self.server = socketserver.ThreadingTCPServer(bind, Handler, bind_and_activate=True)
        self.server.daemon_threads = True
        self.server.allow_reuse_address = False

    @property
    def address(self) -> tuple[str, int]:
        return self.server.server_address

    def serve_forever(self) -> None:
        self.server.serve_forever(poll_interval=0.1)

    def shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
