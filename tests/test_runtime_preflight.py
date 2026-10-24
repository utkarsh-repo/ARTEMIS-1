import json
import pathlib
import subprocess
import sys


def test_runtime_preflight_reports_missing_host_capabilities_without_mutation():
    root = pathlib.Path(__file__).resolve().parents[1]
    script = root / "scripts" / "real-runtime-preflight.py"
    result = subprocess.run([sys.executable, str(script), "--json"], cwd=root,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=15, check=False, shell=False)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert set(report["readiness"]) == {
        "real_container_tests", "network_namespace_tests", "host_firewall_tests", "full_isolation_gate"
    }
    assert "note" in report and "does not" in report["note"]
    assert "container_runtime" in report and "network_namespace" in report and "nftables" in report
