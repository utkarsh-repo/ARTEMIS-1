# ARTEMIS real-runtime verification protocol

**Prepared:** 2026-10-24  
**Baseline artifact:** `ARTEMIS-appsec-2.2.29.zip`  
**Working source:** clean extraction of the baseline artifact; no Git metadata is present.  
**Purpose:** reproducible local verification only. Never point this harness at a public or production target.

## Test classes and evidence labels

| Class | Command | What it proves | What it does not prove |
|---|---|---|---|
| Unit tests | `python -m pytest -q tests --ignore=tests/integration` | Deterministic policy, store, parser, and helper behavior | OS isolation, runtime enforcement, network controls |
| Fake-runtime tests | `python -m pytest -q tests/test_worker_supervisor.py tests/test_dispatcher.py` | Command construction and control flow against a test double | Actual process/container behavior |
| Real-container tests | `ARTEMIS_RUN_CONTAINER_INTEGRATION=1 ARTEMIS_WORKER_IMAGE="$ARTEMIS_WORKER_IMAGE" ARTEMIS_CONTAINER_RUNTIME=podman python -m pytest -q tests/integration/test_container_runtime.py -rs` | Actual configured supervisor invocation, container restrictions, resource limits, direct-socket denial, timeout and cancellation | Host firewall rules for a worker subnet, arbitrary HTTPS transparent capture, scanner correctness |
| Network namespace/firewall preflight | `python scripts/real-runtime-preflight.py --json`; strict gate: `python scripts/real-runtime-preflight.py --require-runtime` | Read-only discovery of runtime, namespace, and nftables capabilities | Does not apply rules or claim enforcement |
| End-to-end assessment tests | `python -m pytest -q tests/test_dispatcher.py tests/test_authorization.py tests/test_runtime_store.py tests/test_evidence_lifecycle.py` | Current deterministic queue/authorization/store/evidence behavior in tests | Real queue-to-isolated-worker execution: production dispatch intentionally does not invoke the supervisor as an authorized action handler |

The integration suite uses a locally built fixture image. It is opt-in; every skipped real-runtime test must be reported as skipped, never counted as passing. A passing real-container suite is necessary but not sufficient to close the parent isolation requirements: egress policy, host firewall boundary, queue cancellation/recovery, and worker-result persistence need their own evidence.

## Host preflight result for this environment

The following result was recorded on the baseline host using `scripts/real-runtime-preflight.py --json`:

- Linux kernel `6.18.55`, Debian 13, Python `3.13.5`, UID 0, cgroup v2 present.
- Docker/Podman executable: unavailable.
- `nft`: unavailable.
- `unshare -n true`: exit code 1, `Operation not permitted`.
- `ip -brief link show`: available, but interface inspection does not grant namespace/firewall capabilities. `nuclei`, `zap`, and `trivy` executables are not installed.
- `full_isolation_gate`: false. No host rules were changed and no container/network isolation claim is made.

The exact observed effective capability mask was `00000000800405fb`. Being UID 0 in this container is not equivalent to having `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` or a usable container runtime.

## Reproduce on a disposable Linux VM

Use a dedicated VM, not a production host. Install a supported rootful Podman or Docker engine, `nftables`, `iproute2`, Python 3.11+ and pytest. Configure the VM so root can create network namespaces and apply firewall rules. Snapshot the VM before the exercise. Do not use `--privileged` for ARTEMIS worker containers.

### 1. Confirm capabilities

```sh
python scripts/real-runtime-preflight.py --json
python scripts/real-runtime-preflight.py --require-runtime
podman info                 # or: docker info
nft --version
unshare -n true
```

The strict preflight must return exit code 0 before attempting network-isolation experiments. If it returns 2, record the exact missing prerequisites and stop; do not bypass it.

### 2. Build and pin the test fixture image

The fixture is `tests/fixtures/worker/Dockerfile` and `worker.py`. It only performs local process/filesystem/network-denial probes; it has no scanner and no public target configured. Use a local registry reachable only from the VM, and ensure the runtime treats that registry as a local insecure test registry only if using plain HTTP. Do not change a shared/production daemon configuration.

Example with Podman and a temporary local registry:

```sh
podman run -d --name artemis-test-registry -p 127.0.0.1:5000:5000 docker.io/library/registry:2
podman build -f tests/fixtures/worker/Dockerfile -t localhost:5000/artemis-worker:2.2.30 tests/fixtures/worker
podman push --tls-verify=false --digestfile /tmp/artemis-worker.digest localhost:5000/artemis-worker:2.2.30 docker://127.0.0.1:5000/artemis-worker:2.2.30
DIGEST=$(cat /tmp/artemis-worker.digest)
IMAGE="127.0.0.1:5000/artemis-worker@${DIGEST}"
podman pull --tls-verify=false "$IMAGE"
podman image inspect "$IMAGE"
```

Verify that the inspected `RepoDigests` contains the exact reference before running tests. If the runtime does not report the pinned manifest digest, stop rather than weakening the digest check. For Docker, configure an isolated local registry using the daemon's documented `insecure-registries` setting for this loopback address only, then push/pull and inspect the digest; restore the prior daemon configuration afterward.

### 3. Run actual supervisor integration tests

```sh
export ARTEMIS_RUN_CONTAINER_INTEGRATION=1
export ARTEMIS_CONTAINER_RUNTIME="$(command -v podman || command -v docker)"
export ARTEMIS_WORKER_IMAGE="$IMAGE"
python -m pytest -vv -rs tests/integration/test_container_runtime.py
```

The tests call `ContainerWorkerSupervisor.run()` and `.cancel()` directly. They assert non-root UID, zero effective capabilities, `NoNewPrivs`, read-only root filesystem, writable bounded tmpfs, cgroup memory/CPU/PID ceilings, direct IPv4/IPv6 socket denial, timeout cleanup, cancellation, and absence of a completion result after cancellation. Runtime-specific metadata differences must be investigated rather than weakening assertions.

### 4. Network boundary test policy

The current supervisor deliberately uses `--network=none` and refuses `network_required=True`. This is fail-closed for offline worker actions, not a functioning allowlisted egress broker. `scoped_egress.py` and `scripts/worker-egress-firewall.py` are not wired as the only route for a real worker. Do not enable scanner or MCP network calls until a dedicated worker subnet, broker-only route, host default-deny policy, IPv4/IPv6 handling, policy-change invalidation, and direct-socket bypass tests have been independently verified.

Firewall rule generation remains dry-run by default. Applying rules is a manual operation with host-level consequences and is deliberately not part of automated tests. Before any manual test, review `python scripts/worker-egress-firewall.py --help`, use a disposable VM, choose a dedicated subnet and broker address, save the current firewall configuration, and prepare rollback. Do not use a broad/shared subnet or run `--apply` against a host with unrelated workloads.

## Baseline test-count discrepancy

The clean v2.2.29 extraction runs `python -m pytest -q --disable-warnings --maxfail=1` with **210 passed, 1 skipped, and 11 subtests passed**. The available clean v2.2.28 extraction produces the same result. The earlier report of 208 passing tests cannot be reproduced from either archive and is treated as a reporting error, not as two tests newly added by v2.2.29. The skipped test in the baseline is the opt-in real-container test; it is not a pass.

## Release evidence template

For every host run, attach the raw preflight JSON, Python/runtime versions, exact image digest, complete command, exit status, test summary including skips, runtime logs with secrets removed, inspected container configuration, and firewall state before/after. Record real-runtime and fake-runtime evidence separately. Never store raw authorization tokens or unredacted target traffic in the report.
