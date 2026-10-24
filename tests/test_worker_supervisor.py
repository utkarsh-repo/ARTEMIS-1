import json
import threading
import time

import pytest

from appsec_agent.worker_supervisor import ContainerWorkerSupervisor, SupervisorError, WorkerLimits

IMAGE = "registry.invalid/artemis-worker@sha256:" + "a" * 64


def fake_runtime(tmp_path, mode="ok"):
    script = tmp_path / "fake-container-runtime"
    log_path = str(tmp_path / "runtime.log")
    script.write_text(f"""#!/usr/bin/env python3
import json, sys, time
args=sys.argv[1:]
with open({log_path!r}, 'a') as f: f.write(json.dumps(args)+'\\n')
if args[:2]==['image','inspect']:
    print(json.dumps([{{'RepoDigests': [{IMAGE!r}]}}]))
    raise SystemExit(0)
if args and args[0] in ('stop','rm'):
    raise SystemExit(0)
if args and args[0]=='inspect':
    sys.stderr.write('Error: No such container\\n'); raise SystemExit(1)
if {mode!r}=='sleep':
    time.sleep(10)
if {mode!r}=='large':
    sys.stdout.write('x'*20000); sys.stdout.flush(); raise SystemExit(0)
if {mode!r}=='bad':
    print('{{bad'); raise SystemExit(0)
if {mode!r}=='empty-evidence':
    print(json.dumps({{'schema_version':1,'status':'completed','result':{{}},'evidence':[]}})); raise SystemExit(0)
print(json.dumps({{'schema_version':1,'status':'completed','result':{{'ok':True}},'evidence':['ev-123']}}))
""")
    script.chmod(0o755)
    return script


def supervisor(tmp_path, monkeypatch, mode="ok", timeout=2, output=4096):
    runtime = fake_runtime(tmp_path, mode)
    # The fake executable is a test fixture; production still requires a real pinned runtime.
    s = ContainerWorkerSupervisor(image=IMAGE, entrypoint=("/opt/artemis/worker",),
        runtime_path=str(runtime), limits=WorkerLimits(timeout_seconds=timeout,
        output_bytes=output, input_bytes=1024, memory_bytes=128*1024*1024,
        cpu_count=1, pids_limit=8, tmpfs_bytes=1024*1024))
    return s


def test_requires_digest_pinned_image(tmp_path):
    runtime = fake_runtime(tmp_path)
    with pytest.raises(ValueError, match="pinned"):
        ContainerWorkerSupervisor(image="latest", entrypoint=("worker",), runtime_path=str(runtime))


def test_fixed_container_security_flags_and_validated_result(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch)
    result = s.run({"task_id": "task-1"}, execution_id="exec-1")
    assert result["status"] == "completed"
    assert result["evidence"] == ["ev-123"]
    commands = [json.loads(line) for line in (tmp_path / "runtime.log").read_text().splitlines()]
    assert commands[0][:2] == ["image", "inspect"]
    args = next(command for command in commands if command and command[0] == "run")
    for required in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit", "--memory", "--cpus", "--user", "65532:65532"):
        assert required in args
    assert "--pull=never" in args
    assert "--entrypoint" in args
    assert "--privileged" not in args
    assert "--volume" not in args and "-v" not in args


def test_network_actions_fail_closed(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch)
    with pytest.raises(SupervisorError, match="egress proxy"):
        s.run({"target": "https://example.invalid"}, network_required=True)
    assert not (tmp_path / "runtime.log").exists()


def test_timeout_stops_container_and_process(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch, mode="sleep", timeout=0.25)
    with pytest.raises(SupervisorError, match="timeout"):
        s.run({"task_id": "slow"}, execution_id="timeout-1")
    lines = [json.loads(x) for x in (tmp_path / "runtime.log").read_text().splitlines()]
    assert any(x[0] == "stop" for x in lines)
    assert any(x[0] == "rm" and x[1] == "--force" for x in lines)
    assert not s.active_executions()


def test_output_limit_terminates_worker(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch, mode="large", output=1024)
    with pytest.raises(SupervisorError, match="output exceeded"):
        s.run({"task_id": "loud"}, execution_id="large-1")


def test_invalid_result_and_empty_evidence_rejected(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch, mode="bad")
    with pytest.raises(SupervisorError, match="invalid JSON"):
        s.run({})


def test_network_and_untrusted_commands_are_not_task_parameters(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch)
    result = s.run({"task_id": "t", "arguments": ["not-a-command"]})
    assert result["status"] == "completed"
    commands = [json.loads(x) for x in (tmp_path / "runtime.log").read_text().splitlines()]
    command = next(x for x in commands if x and x[0] == "run")
    assert command[command.index("--entrypoint") + 1] == "/opt/artemis/worker"


def test_explicit_cancel_terminates_active_runtime(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch, mode="sleep", timeout=5)
    outcome = {}
    def run():
        try:
            s.run({"task_id": "cancel-me"}, execution_id="cancel-1")
        except BaseException as exc:
            outcome["error"] = exc
    thread = threading.Thread(target=run)
    thread.start()
    deadline = time.monotonic() + 2
    while not s.active_executions() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert "cancel-1" in s.active_executions()
    assert s.cancel("cancel-1") is True
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert "error" in outcome
    lines = [json.loads(x) for x in (tmp_path / "runtime.log").read_text().splitlines()]
    assert any(x[0] == "stop" for x in lines)
    assert any(x[0] == "rm" and x[1] == "--force" for x in lines)
    assert not s.active_executions()


def test_empty_evidence_result_is_not_completion(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch, mode="empty-evidence")
    with pytest.raises(SupervisorError, match="at least one evidence"):
        s.run({"task_id": "no-evidence"})


def test_missing_container_runtime_fails_closed(monkeypatch):
    monkeypatch.setattr("appsec_agent.worker_supervisor.shutil.which", lambda name: None)
    with pytest.raises(SupervisorError, match="no supported container runtime"):
        ContainerWorkerSupervisor(image=IMAGE, entrypoint=("/opt/artemis/worker",))


def test_local_image_digest_mismatch_fails_before_worker_start(tmp_path, monkeypatch):
    runtime = fake_runtime(tmp_path)
    content = runtime.read_text().replace("{'RepoDigests': [" + repr(IMAGE) + "]}", "{'RepoDigests': ['registry.invalid/other@sha256:" + "b"*64 + "']}")
    runtime.write_text(content); runtime.chmod(0o755)
    s = ContainerWorkerSupervisor(image=IMAGE, entrypoint=("/opt/artemis/worker",), runtime_path=str(runtime),
        limits=WorkerLimits(timeout_seconds=1, output_bytes=4096, input_bytes=1024,
            memory_bytes=128*1024*1024, cpu_count=1, pids_limit=8, tmpfs_bytes=1024*1024))
    with pytest.raises(SupervisorError, match="does not match"):
        s.run({"task_id": "must-not-run"})
    commands = [json.loads(x) for x in (tmp_path / "runtime.log").read_text().splitlines()]
    assert all(not (x and x[0] == "run") for x in commands)


def test_container_name_is_stable_for_durable_execution_id(tmp_path, monkeypatch):
    s = supervisor(tmp_path, monkeypatch)
    first = s._container_name("durable-execution-1")
    second = s._container_name("durable-execution-1")
    other = s._container_name("durable-execution-2")
    assert first == second
    assert first != other
    assert first.startswith("artemis-worker-")
    assert len(first) == len("artemis-worker-") + 32


def test_cancel_can_remove_persisted_container_after_supervisor_restart(tmp_path, monkeypatch):
    runtime = tmp_path / "fake-persistent-runtime"
    state = tmp_path / "container-present"
    state.write_text("yes")
    log_path = tmp_path / "persistent-runtime.log"
    runtime.write_text(f'''#!/usr/bin/env python3
import pathlib, sys
args=sys.argv[1:]
with open({str(log_path)!r}, "a") as f: f.write(" ".join(args)+"\\n")
state=pathlib.Path({str(state)!r})
if args and args[0]=="inspect":
    if state.exists(): raise SystemExit(0)
    raise SystemExit(1)
if args and args[0] in ("stop", "rm"):
    state.unlink(missing_ok=True)
    raise SystemExit(0)
raise SystemExit(2)
''')
    runtime.chmod(0o755)
    s = ContainerWorkerSupervisor(image=IMAGE, entrypoint=("/opt/artemis/worker",), runtime_path=str(runtime),
        limits=WorkerLimits(timeout_seconds=1, output_bytes=4096, input_bytes=1024,
            memory_bytes=128*1024*1024, cpu_count=1, pids_limit=8, tmpfs_bytes=1024*1024))
    # No in-memory Popen handle exists: this simulates controller restart.
    assert s.active_executions() == ()
    assert s.cancel("durable-execution") is True
    assert not state.exists()
    commands = log_path.read_text()
    assert "inspect artemis-worker-" in commands
    assert "stop --time 0 artemis-worker-" in commands
    assert "rm --force artemis-worker-" in commands
