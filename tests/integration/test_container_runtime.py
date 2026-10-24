"""Opt-in tests against a real Docker/Podman runtime and a digest-pinned local fixture.

No public or production targets are contacted. Network probes use IANA documentation
addresses only. These tests are deliberately skipped unless every opt-in variable is set.
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import threading
import time
import uuid

import pytest

from appsec_agent.worker_supervisor import ContainerWorkerSupervisor, SupervisorError, WorkerLimits

RUN = os.environ.get("ARTEMIS_RUN_CONTAINER_INTEGRATION") == "1"
IMAGE = os.environ.get("ARTEMIS_WORKER_IMAGE", "")
RUNTIME = os.environ.get("ARTEMIS_CONTAINER_RUNTIME") or shutil.which("podman") or shutil.which("docker")
pytestmark = pytest.mark.skipif(not RUN or not IMAGE or not RUNTIME,
    reason="real runtime unavailable/opt-in disabled; set ARTEMIS_RUN_CONTAINER_INTEGRATION=1, ARTEMIS_WORKER_IMAGE=<local-repo@sha256:digest>, and ARTEMIS_CONTAINER_RUNTIME or install Docker/Podman")


def _run(args, *, timeout=10, check=True):
    return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=check, text=True, shell=False,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})


def _supervisor(*, timeout=10):
    if "@sha256:" not in IMAGE or len(IMAGE.rsplit("@sha256:", 1)[-1]) != 64:
        pytest.fail("ARTEMIS_WORKER_IMAGE must be a full sha256 digest reference")
    return ContainerWorkerSupervisor(image=IMAGE,
        entrypoint=("/usr/local/bin/python3", "/opt/artemis/worker.py"), runtime_path=RUNTIME,
        limits=WorkerLimits(timeout_seconds=timeout, memory_bytes=128*1024*1024, cpu_count=0.5,
            pids_limit=16, tmpfs_bytes=1024*1024, output_bytes=8192, input_bytes=1024))


def _assert_absent(supervisor, execution_id):
    name = supervisor._container_name(execution_id)
    inspected = _run([RUNTIME, "inspect", name], check=False, timeout=5)
    assert inspected.returncode != 0, f"worker container {name} still exists after completion/cancellation"


def test_real_supervisor_enforces_container_controls_and_direct_network_denial():
    supervisor = _supervisor()
    result = supervisor.run({"mode": "probe"}, execution_id="runtime-probe-" + uuid.uuid4().hex[:12])
    probe = result["result"]
    assert probe["uid"] != 0
    assert probe["cap_eff"] == 0
    assert probe["no_new_privs"] is True
    assert probe["rootfs_read_only"] is True
    assert probe["tmpfs_writable"] is True
    assert probe["ipv4_direct_socket_blocked"] is True
    assert probe["ipv6_direct_socket_blocked"] is True
    assert probe["memory_max"] == str(128*1024*1024)
    assert probe["pids_max"] == "16"
    assert probe["cpu_max"] and probe["cpu_max"] != "max"
    _assert_absent(supervisor, result["execution_id"])


def test_real_supervisor_timeout_removes_actual_container():
    supervisor = _supervisor(timeout=1.25)
    execution_id = "runtime-timeout-" + uuid.uuid4().hex[:12]
    with pytest.raises(SupervisorError, match="timeout"):
        supervisor.run({"mode": "sleep", "seconds": 60}, execution_id=execution_id)
    assert execution_id not in supervisor.active_executions()
    _assert_absent(supervisor, execution_id)


def test_real_supervisor_cancel_removes_actual_container_and_rejects_result():
    supervisor = _supervisor(timeout=30)
    execution_id = "runtime-cancel-" + uuid.uuid4().hex[:12]
    outcome = {}
    def execute():
        try:
            outcome["result"] = supervisor.run({"mode": "sleep", "seconds": 60}, execution_id=execution_id)
        except BaseException as exc:  # capture worker thread exception for assertion
            outcome["error"] = exc
    thread = threading.Thread(target=execute, daemon=True)
    thread.start()
    name = supervisor._container_name(execution_id)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        inspected = _run([RUNTIME, "inspect", name], check=False, timeout=2)
        if inspected.returncode == 0:
            break
        if not thread.is_alive():
            pytest.fail(f"worker exited before cancellation: {outcome!r}")
        time.sleep(0.05)
    else:
        pytest.fail("supervisor never created the expected real worker container")
    assert supervisor.cancel(execution_id) is True
    thread.join(timeout=8)
    assert not thread.is_alive(), "supervisor thread did not terminate after cancellation"
    assert "result" not in outcome, "cancelled worker must not return a completion result"
    assert "error" in outcome
    assert execution_id not in supervisor.active_executions()
    _assert_absent(supervisor, execution_id)
