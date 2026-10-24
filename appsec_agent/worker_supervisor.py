"""Fail-closed container supervisor for fixed, offline ARTEMIS worker commands.

The supervisor never accepts an executable or command from a task. Operators
configure a pinned container image and a fixed entrypoint at construction time.
Network access is disabled at the container boundary; network-capable tools must
remain blocked until a separately enforced, policy-aware egress proxy exists.
"""
from __future__ import annotations

import json
import os
import hashlib
import pathlib
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Sequence


class SupervisorError(RuntimeError):
    """Execution could not safely start or did not produce a valid result."""


@dataclass(frozen=True)
class WorkerLimits:
    timeout_seconds: float = 30.0
    memory_bytes: int = 512 * 1024 * 1024
    cpu_count: float = 1.0
    pids_limit: int = 64
    output_bytes: int = 1_000_000
    input_bytes: int = 65_536
    tmpfs_bytes: int = 16 * 1024 * 1024

    def validate(self) -> None:
        if not 0.1 <= self.timeout_seconds <= 900:
            raise ValueError("timeout_seconds must be between 0.1 and 900")
        if not 64 * 1024 * 1024 <= self.memory_bytes <= 8 * 1024**3:
            raise ValueError("memory_bytes must be between 64 MiB and 8 GiB")
        if not 0.1 <= self.cpu_count <= 16:
            raise ValueError("cpu_count must be between 0.1 and 16")
        if not 1 <= self.pids_limit <= 1024:
            raise ValueError("pids_limit must be between 1 and 1024")
        if not 1024 <= self.output_bytes <= 16 * 1024 * 1024:
            raise ValueError("output_bytes must be between 1 KiB and 16 MiB")
        if not 1 <= self.input_bytes <= 1024 * 1024:
            raise ValueError("input_bytes must be between 1 byte and 1 MiB")
        if not 1024 * 1024 <= self.tmpfs_bytes <= 256 * 1024 * 1024:
            raise ValueError("tmpfs_bytes must be between 1 MiB and 256 MiB")


class ContainerWorkerSupervisor:
    """Run a fixed worker in a pinned, no-network container with hard limits.

    `runtime_path`, `image` and `entrypoint` are trusted deployment config, never
    task input. The image must be pinned by SHA-256 digest. This class only
    supports offline tasks: `network_required=True` is rejected unconditionally.
    """

    _DIGEST_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$")

    def __init__(self, *, image: str, entrypoint: Sequence[str], runtime_path: str | None = None,
                 limits: WorkerLimits | None = None):
        if not isinstance(image, str) or not self._DIGEST_IMAGE.fullmatch(image):
            raise ValueError("worker image must be pinned with @sha256:<64 lowercase hex chars>")
        if not entrypoint or any(not isinstance(x, str) or not x or "\x00" in x for x in entrypoint):
            raise ValueError("entrypoint must be a non-empty fixed argument sequence")
        if runtime_path is None:
            runtime_path = shutil.which("podman") or shutil.which("docker")
        if not runtime_path:
            raise SupervisorError("no supported container runtime (Podman or Docker) is installed")
        path = pathlib.Path(runtime_path)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("runtime_path must be an absolute executable file")
        self.runtime_path = str(path)
        self.image = image
        self.entrypoint = tuple(entrypoint)
        self.limits = limits or WorkerLimits()
        self.limits.validate()
        self._active: dict[str, tuple[subprocess.Popen, str]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _container_name(execution_id: str) -> str:
        """Derive a stable, non-secret runtime name from a validated execution ID."""
        if not isinstance(execution_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", execution_id):
            raise ValueError("invalid execution_id")
        suffix = hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:32]
        return "artemis-worker-" + suffix

    def _command(self, container_name: str) -> list[str]:
        limits = self.limits
        # No host mounts, no host network, no privileged mode, and no environment
        # inherited from the planner/operator. The image's default seccomp profile
        # is retained; capabilities and privilege escalation are disabled.
        return [self.runtime_path, "run", "--rm", "--pull=never", "--interactive", "--name", container_name,
                "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--pids-limit", str(limits.pids_limit), "--memory", str(limits.memory_bytes),
                "--memory-swap", str(limits.memory_bytes), "--cpus", str(limits.cpu_count),
                "--user", "65532:65532", "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_bytes}",
                "--workdir", "/tmp", "--entrypoint", self.entrypoint[0], self.image, *self.entrypoint[1:]]

    def run(self, payload: dict[str, Any], *, execution_id: str | None = None,
            network_required: bool = False) -> dict[str, Any]:
        """Execute one JSON payload. Raises on timeout, cancellation, output overflow or bad result."""
        if network_required:
            raise SupervisorError("network-capable actions are blocked: no externally enforced scoped egress proxy is configured")
        if not isinstance(payload, dict):
            raise ValueError("worker payload must be a JSON object")
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        except (TypeError, ValueError) as exc:
            raise ValueError("worker payload must contain finite JSON values only") from exc
        if len(encoded) > self.limits.input_bytes:
            raise ValueError("worker payload exceeds configured input limit")
        execution_id = execution_id or uuid.uuid4().hex
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", execution_id):
            raise ValueError("invalid execution_id")
        # Never pull on demand. Inspect the already-local image and verify its
        # repository digest before creating a worker; a digest-shaped string
        # alone is not proof that the local image resolves to that digest.
        self._verify_local_image_digest()
        # Runtime names are derived internally, never interpolated into a shell.
        # Stable execution-derived names allow a restarted controller to locate
        # a leftover container instead of losing its only cancellation handle.
        container_name = self._container_name(execution_id)
        with self._lock:
            if execution_id in self._active:
                raise SupervisorError("execution_id is already active")
        with tempfile.TemporaryFile(mode="w+b") as stdin_file:
            stdin_file.write(encoded)
            stdin_file.seek(0)
            try:
                proc = subprocess.Popen(self._command(container_name), stdin=stdin_file,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                    close_fds=True, start_new_session=(os.name == "posix"),
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
            except OSError as exc:
                raise SupervisorError(f"container runtime failed to start: {type(exc).__name__}") from exc
            with self._lock:
                self._active[execution_id] = (proc, container_name)
            stdout = bytearray(); stderr = bytearray()
            selector = selectors.DefaultSelector()
            assert proc.stdout is not None and proc.stderr is not None
            os.set_blocking(proc.stdout.fileno(), False)
            os.set_blocking(proc.stderr.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, stdout)
            selector.register(proc.stderr, selectors.EVENT_READ, stderr)
            deadline = time.monotonic() + self.limits.timeout_seconds
            try:
                while selector.get_map() or proc.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._terminate(execution_id, proc, container_name)
                        raise SupervisorError("worker wall-clock timeout exceeded")
                    for key, _ in selector.select(min(0.05, remaining)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        bucket = key.data
                        bucket.extend(chunk)
                        if len(stdout) + len(stderr) > self.limits.output_bytes:
                            self._terminate(execution_id, proc, container_name)
                            raise SupervisorError("worker output exceeded configured limit")
                    if proc.poll() is not None and not selector.get_map():
                        break
                returncode = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except BaseException:
                if proc.poll() is None:
                    self._terminate(execution_id, proc, container_name)
                raise
            finally:
                selector.close()
                with self._lock:
                    self._active.pop(execution_id, None)
                proc.stdout.close(); proc.stderr.close()
        if returncode != 0:
            # Do not echo arbitrary stderr into logs; callers receive a bounded safe diagnostic.
            raise SupervisorError(f"worker container exited with status {returncode}")
        try:
            result = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SupervisorError("worker returned invalid JSON") from exc
        if not isinstance(result, dict) or result.get("schema_version") != 1 or result.get("status") != "completed":
            raise SupervisorError("worker result failed the completion contract")
        if set(result) != {"schema_version", "status", "result", "evidence"}:
            raise SupervisorError("worker result contains missing or unexpected fields")
        if not isinstance(result["evidence"], list) or not result["evidence"]:
            raise SupervisorError("worker completion requires at least one evidence reference")
        if any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", item) for item in result["evidence"]):
            raise SupervisorError("worker evidence references are malformed")
        return {"execution_id": execution_id, **result, "container_exit_code": returncode,
                "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}

    def _verify_local_image_digest(self) -> None:
        """Require the local image metadata to contain the exact pinned digest."""
        try:
            inspected = subprocess.run([self.runtime_path, "image", "inspect", self.image],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5, check=False, shell=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SupervisorError("could not verify local pinned worker image") from exc
        if inspected.returncode != 0:
            raise SupervisorError("pinned worker image is not present locally or inspection failed")
        try:
            metadata = json.loads(inspected.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SupervisorError("container runtime returned invalid image metadata") from exc
        records = metadata if isinstance(metadata, list) else [metadata]
        expected = self.image.rsplit("@", 1)[1]
        matched = False
        for record in records:
            if not isinstance(record, dict):
                continue
            digests = record.get("RepoDigests", record.get("repoDigests", record.get("repo_digests", [])))
            if isinstance(digests, list) and any(isinstance(item, str) and item.rsplit("@", 1)[-1] == expected for item in digests):
                matched = True
            if record.get("Digest") == expected or record.get("digest") == expected:
                matched = True
        if not matched:
            raise SupervisorError("local worker image digest does not match the configured pin")

    def _terminate(self, execution_id: str, proc: subprocess.Popen, container_name: str) -> None:
        """Stop and remove the actual container, then verify the runtime process exited."""
        cleanup_errors = []
        for command in ([self.runtime_path, "stop", "--time", "0", container_name],
                        [self.runtime_path, "rm", "--force", container_name]):
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=2, check=False, shell=False,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                # `stop` can legitimately fail if already stopped; forced removal
                # must succeed for cleanup to be considered confirmed.
                if command[1] == "rm":
                    try:
                        inspected = subprocess.run([self.runtime_path, "inspect", container_name],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            timeout=2, check=False, shell=False,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                        if inspected.returncode == 0:
                            cleanup_errors.append("container still exists after forced removal")
                        else:
                            diagnostic = inspected.stderr.decode("utf-8", "replace").lower()
                            absent_markers = ("no such container", "no container with name", "container not found", "does not exist")
                            if not any(marker in diagnostic for marker in absent_markers):
                                cleanup_errors.append("runtime could not confirm whether the container still exists")
                    except (OSError, subprocess.TimeoutExpired):
                        cleanup_errors.append("container removal could not be confirmed")
            except (OSError, subprocess.TimeoutExpired):
                if command[1] == "rm":
                    cleanup_errors.append("container removal could not be confirmed")
        if proc.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except (ProcessLookupError, PermissionError, OSError):
                try: proc.kill()
                except OSError: pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                cleanup_errors.append("container runtime process did not exit after kill")
        if proc.poll() is None:
            cleanup_errors.append("container runtime process remains alive")
        if cleanup_errors:
            raise SupervisorError("worker termination could not be confirmed: " + "; ".join(cleanup_errors))

    def cancel(self, execution_id: str) -> bool:
        """Cancel an execution and confirm container/runtime termination.

        Stable names permit cleanup after controller restart even when the local
        Popen handle is gone. False means no matching live container was found;
        callers must not treat that as proof that a prior execution completed.
        """
        name = self._container_name(execution_id)
        with self._lock:
            active = self._active.get(execution_id)
        if active:
            proc, active_name = active
            self._terminate(execution_id, proc, active_name)
            return True
        try:
            inspected = subprocess.run([self.runtime_path, "inspect", name], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=False, shell=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SupervisorError("could not inspect persisted worker container during cancellation") from exc
        if inspected.returncode != 0:
            return False
        self._terminate_container_only(name)
        return True

    def _terminate_container_only(self, container_name: str) -> None:
        """Stop/remove a persisted container and verify it is absent afterwards."""
        for command in ([self.runtime_path, "stop", "--time", "0", container_name],
                        [self.runtime_path, "rm", "--force", container_name]):
            try:
                subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=3, check=False, shell=False,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SupervisorError("container termination command could not be confirmed") from exc
        try:
            after = subprocess.run([self.runtime_path, "inspect", container_name], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=False, shell=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SupervisorError("could not verify container removal") from exc
        if after.returncode == 0:
            raise SupervisorError("worker container remains after cancellation")

    def active_executions(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._active))
