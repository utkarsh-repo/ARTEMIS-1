#!/usr/bin/env python3
"""Report, without changing host state, whether ARTEMIS runtime tests can run."""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys


def command_result(args: list[str], timeout: float = 3.0) -> dict:
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout, check=False, shell=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        return {"available": True, "exit_code": result.returncode,
                "stdout": result.stdout.strip()[-1200:], "stderr": result.stderr.strip()[-1200:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "error": type(exc).__name__ + ": " + str(exc)[:300]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable report")
    parser.add_argument("--require-runtime", action="store_true", help="exit 2 unless runtime and namespace/firewall prerequisites are available")
    args = parser.parse_args()
    runtime = shutil.which("docker") or shutil.which("podman")
    report = {
        "host": {"platform": sys.platform, "kernel": os.uname().release if hasattr(os, "uname") else None,
                 "python": sys.version.split()[0], "uid": os.geteuid() if hasattr(os, "geteuid") else None,
                 "effective_capabilities": next((line.split(":", 1)[1].strip() for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')), None),
                 "cgroup_v2": pathlib.Path('/sys/fs/cgroup/cgroup.controllers').exists()},
        "container_runtime": {"path": runtime, "daemon_or_service": command_result([runtime, "info"], timeout=8) if runtime else {"available": False, "error": "Docker/Podman executable not found"}},
        "nftables": {"path": shutil.which("nft"), "version": command_result([shutil.which("nft"), "--version"]) if shutil.which("nft") else {"available": False, "error": "nft executable not found"}},
        "network_namespace": command_result([shutil.which("unshare") or "/usr/bin/unshare", "-n", "true"], timeout=3),
        "ip": {"path": shutil.which("ip"), "link": command_result([shutil.which("ip"), "-brief", "link", "show"]) if shutil.which("ip") else {"available": False, "error": "ip executable not found"}},
        "scanner_tools": {name: {"path": shutil.which(name), "available": bool(shutil.which(name))}
                          for name in ("nuclei", "zap", "trivy")},
        "note": "Read-only preflight. It does not build images, start containers, create namespaces, or alter firewall rules."
    }
    runtime_ok = bool(runtime and report["container_runtime"]["daemon_or_service"].get("exit_code") == 0)
    namespace_ok = report["network_namespace"].get("exit_code") == 0
    firewall_ok = bool(shutil.which("nft") and report["nftables"]["version"].get("exit_code") == 0)
    report["readiness"] = {"real_container_tests": runtime_ok, "network_namespace_tests": namespace_ok,
                           "host_firewall_tests": firewall_ok, "full_isolation_gate": runtime_ok and namespace_ok and firewall_ok and report["host"]["cgroup_v2"]}
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else _human(report))
    if args.require_runtime and not report["readiness"]["full_isolation_gate"]:
        return 2
    return 0


def _human(report: dict) -> str:
    readiness = report["readiness"]
    lines = ["ARTEMIS real-runtime preflight (read-only)"]
    for key, value in readiness.items():
        lines.append(f"{key}: {'READY' if value else 'UNAVAILABLE'}")
    for key in ("container_runtime", "nftables", "network_namespace"):
        lines.append(f"{key}: {json.dumps(report[key], sort_keys=True)}")
    lines.append(report["note"])
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
