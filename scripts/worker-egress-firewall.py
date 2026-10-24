#!/usr/bin/env python3
"""Generate/apply narrowly scoped nftables rules for an ARTEMIS worker subnet.

Default is dry-run. Example:
  sudo python scripts/worker-egress-firewall.py --worker-subnet 172.30.0.0/24 \
    --proxy-ip 172.30.0.1 --proxy-port 3128
  sudo python scripts/worker-egress-firewall.py --worker-subnet 172.30.0.0/24 \
    --proxy-ip 172.30.0.1 --proxy-port 3128 --apply

The subnet must be dedicated to workers. This script never changes default
policies for unrelated traffic. Review the printed rules before --apply.
"""
from __future__ import annotations
import argparse
import ipaddress
import shutil
import subprocess
import sys

TABLE = "artemis_worker_egress"


def build_rules(subnet_text: str, proxy_text: str, port: int) -> str:
    subnet = ipaddress.ip_network(subnet_text, strict=True)
    proxy = ipaddress.ip_address(proxy_text)
    if subnet.version != proxy.version:
        raise ValueError("worker subnet and proxy IP must use the same IP version")
    if not 1 <= port <= 65535:
        raise ValueError("proxy port must be between 1 and 65535")
    source = "ip saddr" if subnet.version == 4 else "ip6 saddr"
    destination = "ip daddr" if proxy.version == 4 else "ip6 daddr"
    return f'''table inet {TABLE} {{
  chain input {{
    type filter hook input priority -10; policy accept;
    {source} {subnet} {destination} {proxy} tcp dport {port} accept
    {source} {subnet} drop
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    {source} {subnet} {destination} {proxy} tcp dport {port} accept
    {source} {subnet} drop
  }}
}}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-subnet", required=True)
    parser.add_argument("--proxy-ip", required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--apply", action="store_true", help="apply rules (otherwise print and validate only)")
    args = parser.parse_args()
    try:
        rules = build_rules(args.worker_subnet, args.proxy_ip, args.proxy_port)
    except ValueError as exc:
        parser.error(str(exc))
    print(rules, end="")
    if not args.apply:
        print("DRY RUN: no firewall changes made", file=sys.stderr)
        return 0
    if not shutil.which("nft"):
        print("ERROR: nftables executable not found; no changes made", file=sys.stderr)
        return 2
    if not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() != 0:
        print("ERROR: --apply requires root; no changes made", file=sys.stderr)
        return 2
    # Refuse to overwrite an existing table. A rollback must be performed by the operator.
    exists = subprocess.run(["nft", "list", "table", "inet", TABLE], capture_output=True, check=False)
    if exists.returncode == 0:
        print(f"ERROR: table inet {TABLE} already exists; inspect it before changing anything", file=sys.stderr)
        return 2
    applied = subprocess.run(["nft", "-f", "-"], input=rules.encode(), capture_output=True, check=False)
    if applied.returncode:
        print("ERROR: nftables rejected the rules; no success reported", file=sys.stderr)
        print(applied.stderr.decode("utf-8", "replace")[-1000:], file=sys.stderr)
        return applied.returncode
    verify = subprocess.run(["nft", "list", "table", "inet", TABLE], capture_output=True, check=False)
    if verify.returncode:
        print("ERROR: applied table could not be verified; inspect host firewall immediately", file=sys.stderr)
        return verify.returncode
    print("Applied and verified dedicated ARTEMIS worker egress rules", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
