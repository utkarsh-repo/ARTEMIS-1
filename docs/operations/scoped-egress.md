# Scoped worker egress deployment (v2.2.8)

## Security status

ARTEMIS currently keeps the worker supervisor at `--network=none`. This is the safe default. `appsec_agent/scoped_egress.py` adds a policy-aware CONNECT broker that validates the assessment/policy version on every tunnel, requires an exact host and port, validates every DNS answer, signs in-process decisions, pins the socket to a previously authorized IP, and emits allow/deny audit events. It is **not** by itself an enforced network boundary and is not wired to the worker supervisor in this release.

HTTPS CONNECT cannot inspect encrypted URL paths or HTTP methods. The HTTP client must continue to enforce method/path scope and disable redirects (`allow_redirects=False`). A redirect must be treated as a new request and reauthorized. The broker denies non-CONNECT plaintext proxy requests.

## Required deployment topology

1. Use a dedicated container network/subnet only for ARTEMIS workers. Do not share it with unrelated workloads.
2. Keep worker networking disabled until a deployment operator configures the worker to reach only the broker and applies the host firewall rules below.
3. Run the broker in a separately controlled service. Its live-context callback must load the current assessment ID and policy digest from trusted runtime state; if that lookup fails or either value changes, the broker denies new tunnels. Do not take these values from worker headers.
4. Configure exact lowercase hosts and explicit ports per assessment. Do not use wildcard hosts or a global allow-private setting. Private targets require explicit CIDR exceptions and should only be used for isolated labs.
5. Configure the host firewall to permit worker-subnet traffic only to the broker endpoint, then drop all other worker-subnet input/forward traffic. The broker itself must use the validated pinned-destination policy.
6. Do not enable network-capable worker execution until real-runtime integration tests pass on the actual host/network configuration.

## Firewall rule generator

`scripts/worker-egress-firewall.py` prints rules and makes no changes by default. Review the generated rules and use a dedicated worker subnet and broker endpoint:

```sh
sudo python scripts/worker-egress-firewall.py \
  --worker-subnet 172.30.0.0/24 \
  --proxy-ip 172.30.0.1 \
  --proxy-port 3128
```

Only after review, apply explicitly:

```sh
sudo python scripts/worker-egress-firewall.py \
  --worker-subnet 172.30.0.0/24 \
  --proxy-ip 172.30.0.1 \
  --proxy-port 3128 \
  --apply
```

This installs a dedicated `inet artemis_worker_egress` table and refuses to overwrite an existing table. It drops worker-subnet input and forwarding except traffic to the configured proxy IP/port. It does not create a container network, configure the broker, or restrict the broker process's own outbound traffic. Verify the rules and topology independently before enabling worker network access. Rollback is an explicit operator action: inspect and remove only `table inet artemis_worker_egress` if it is confirmed to be the table created for this deployment.

## Validation

Unit tests use deterministic DNS fixtures and a loopback echo server with an explicit `127.0.0.1/32` lab exception; they do not contact public targets. The opt-in `tests/integration/test_container_runtime.py` exercises a real local Docker/Podman runtime and a digest-pinned local image. It is skipped unless `ARTEMIS_RUN_CONTAINER_INTEGRATION=1` and `ARTEMIS_WORKER_IMAGE` are supplied. It probes only the documentation-only `192.0.2.1` address and checks non-root UID, read-only root, zero effective capabilities, no-new-privileges, resource limits and network denial.

The current development environment has no supported container runtime and does not grant network namespace creation. Therefore real runtime isolation, host firewall enforcement, and queue-to-supervisor cancellation are **not verified here**. The worker supervisor remains network-disabled and the authorization gateway continues to block before handler dispatch.
