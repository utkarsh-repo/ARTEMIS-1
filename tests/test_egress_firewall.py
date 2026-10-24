import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "worker-egress-firewall.py"
spec = importlib.util.spec_from_file_location("worker_egress_firewall", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_firewall_rules_allow_only_worker_to_proxy_and_drop_forwarding():
    rules = module.build_rules("172.30.0.0/24", "172.30.0.1", 3128)
    assert "table inet artemis_worker_egress" in rules
    assert "ip saddr 172.30.0.0/24 ip daddr 172.30.0.1 tcp dport 3128 accept" in rules
    assert "ip saddr 172.30.0.0/24 drop" in rules
    assert rules.count("drop") == 2


def test_firewall_rules_support_ipv6_and_reject_family_mismatch():
    rules = module.build_rules("fd00:1234::/64", "fd00:1234::1", 3128)
    assert "ip6 saddr fd00:1234::/64 ip6 daddr fd00:1234::1 tcp dport 3128 accept" in rules
    with pytest.raises(ValueError, match="same IP version"):
        module.build_rules("172.30.0.0/24", "fd00::1", 3128)


def test_firewall_port_is_bounded():
    with pytest.raises(ValueError, match="proxy port"):
        module.build_rules("172.30.0.0/24", "172.30.0.1", 65536)
