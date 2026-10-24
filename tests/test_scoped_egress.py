import socket
import socketserver
import threading

import pytest

from appsec_agent.policy import PolicyError
from appsec_agent.scoped_egress import EgressDecision, ScopedConnectProxy, ScopedEgressPolicy


def _answer(ip):
    def resolve(host, port, type=None):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    return resolve


def test_exact_host_port_and_current_assessment_policy_are_required():
    events = []
    gate = ScopedEgressPolicy(assessment_id="job-1", policy_digest="sha256:abc",
        allowed_hosts=["approved.example"], allowed_ports=[443], resolver=_answer("93.184.216.34"), audit=events.append)
    assert gate.authorize("approved.example", 443, assessment_id="job-1", policy_digest="sha256:abc").allowed
    assert not gate.authorize("attacker.example", 443, assessment_id="job-1", policy_digest="sha256:abc").allowed
    assert not gate.authorize("approved.example", 8443, assessment_id="job-1", policy_digest="sha256:abc").allowed
    assert not gate.authorize("approved.example", 443, assessment_id="job-2", policy_digest="sha256:abc").allowed
    assert not gate.authorize("approved.example", 443, assessment_id="job-1", policy_digest="sha256:changed").allowed
    assert any(e["event"] == "egress_deny" for e in events)


def test_private_dns_answer_denied_without_exact_cidr_exception():
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["approved.example"],
        resolver=_answer("127.0.0.1"), audit=lambda _: None)
    result = gate.authorize("approved.example", 443, assessment_id="job", policy_digest="p")
    assert not result.allowed
    assert "prohibited" in result.reason


def test_mixed_public_and_private_dns_answers_fail_closed():
    def resolver(host, port, type=None):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["approved.example"],
        resolver=resolver, audit=lambda _: None)
    assert not gate.authorize("approved.example", 443, assessment_id="job", policy_digest="p").allowed


def test_pinned_connect_uses_previously_authorized_ip_and_rejects_stale_decision():
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["approved.example"],
        resolver=_answer("93.184.216.34"), audit=lambda _: None)
    decision = gate.authorize("approved.example", 443, assessment_id="job", policy_digest="p")
    stale = ScopedEgressPolicy(assessment_id="job", policy_digest="new", allowed_hosts=["approved.example"],
        resolver=_answer("93.184.216.34"), audit=lambda _: None)
    with pytest.raises(PolicyError, match="invalid or stale"):
        stale.connect_pinned(decision)


def test_connect_proxy_enforces_scope_and_can_tunnel_to_explicit_lab_cidr():
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(self.request.recv(16))
    echo_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    echo_thread = threading.Thread(target=echo_server.serve_forever, daemon=True)
    echo_thread.start()
    port = echo_server.server_address[1]
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["lab.example"],
        allowed_ports=[port], allowed_private_cidrs=["127.0.0.1/32"], resolver=_answer("127.0.0.1"), audit=lambda _: None)
    proxy = ScopedConnectProxy(gate, assessment_id="job", policy_digest="p", current_context=lambda: ("job", "p"))
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        client = socket.create_connection(proxy.address, timeout=2)
        client.sendall(f"CONNECT lab.example:{port} HTTP/1.1\r\nHost: lab.example:{port}\r\n\r\n".encode())
        response = client.recv(1024)
        assert b"200 Connection Established" in response
        client.sendall(b"ping")
        assert client.recv(16) == b"ping"
        client.close()

        denied = socket.create_connection(proxy.address, timeout=2)
        denied.sendall(f"CONNECT other.example:{port} HTTP/1.1\r\nHost: other.example:{port}\r\n\r\n".encode())
        assert b"403 Forbidden" in denied.recv(1024)
        denied.close()
    finally:
        proxy.shutdown()
        echo_server.shutdown(); echo_server.server_close()


def test_proxy_rejects_plain_http_and_malformed_authority():
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["lab.example"],
        resolver=_answer("93.184.216.34"), audit=lambda _: None)
    proxy = ScopedConnectProxy(gate, assessment_id="job", policy_digest="p", current_context=lambda: ("job", "p"))
    thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start()
    try:
        client = socket.create_connection(proxy.address, timeout=2)
        client.sendall(b"GET http://lab.example/ HTTP/1.1\r\nHost: lab.example\r\n\r\n")
        assert b"403 Forbidden" in client.recv(1024)
        client.close()
    finally:
        proxy.shutdown()


def test_forged_egress_decision_cannot_be_used_to_open_socket():
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["approved.example"],
        resolver=_answer("93.184.216.34"), audit=lambda _: None)
    forged = EgressDecision(True, "job", "p", "approved.example", 443, ("127.0.0.1",), "allowed", "forged")
    with pytest.raises(PolicyError, match="invalid or stale"):
        gate.connect_pinned(forged)


def test_trailing_dot_hostname_is_rejected_as_ambiguous():
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["approved.example"],
        resolver=_answer("93.184.216.34"), audit=lambda _: None)
    result = gate.authorize("approved.example.", 443, assessment_id="job", policy_digest="p")
    assert not result.allowed
    assert result.reason == "ambiguous_host"


def test_proxy_denies_when_live_policy_context_changes():
    gate = ScopedEgressPolicy(assessment_id="job", policy_digest="p", allowed_hosts=["lab.example"],
        resolver=_answer("93.184.216.34"), audit=lambda _: None)
    proxy = ScopedConnectProxy(gate, assessment_id="job", policy_digest="p", current_context=lambda: ("job", "changed"))
    thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start()
    try:
        client = socket.create_connection(proxy.address, timeout=2)
        client.sendall(b"CONNECT lab.example:443 HTTP/1.1\r\nHost: lab.example:443\r\n\r\n")
        assert b"403 Forbidden" in client.recv(1024)
        client.close()
    finally:
        proxy.shutdown()
