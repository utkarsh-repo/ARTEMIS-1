"""Durable queue-to-authorization dispatch coordinator.

This coordinator deliberately does not make network execution available. It
claims only registered tool-action tasks, consumes approval through the central
gateway, and then asks the gateway to revalidate immediately before execution.
The gateway remains fail-closed until an independently enforced worker/egress
boundary is configured. This makes the queue integration observable without
silently falling back to in-process handlers.
"""
from __future__ import annotations

from typing import Any

from .authorization import AuthorizationDenied, AuthorizationGateway
from .runtime_store import RuntimeStore, policy_digest
from .worker_supervisor import ContainerWorkerSupervisor, SupervisorError


class QueueDispatcher:
    """Claim and authorize one task; dispatch only if the gateway permits it."""

    def __init__(self, store: RuntimeStore, policy: dict[str, Any], *,
                 supervisor: ContainerWorkerSupervisor | None = None):
        self.store = store
        self.policy = policy
        self.supervisor = supervisor
        self.gateway = AuthorizationGateway(store, policy)
        if supervisor is not None:
            # RuntimeStore refuses to acknowledge cancellation without this
            # callback confirming that the corresponding container is gone.
            store.register_execution_canceller(supervisor.cancel)

    def dispatch_once(self, worker_id: str, *, lease_seconds: int = 60,
                      job_id: str | None = None) -> dict[str, Any]:
        """Process one tool_action task or return an explicit idle/blocked result.

        No arbitrary handler lookup is performed. The registry/gateway remains
        the source of tool identity, schema, scope and approval truth.
        """
        digest = policy_digest(self.policy)
        task = self.store.claim_next(worker_id, expected_policy_digest=digest,
                                     lease_seconds=lease_seconds, job_id=job_id,
                                     task_type="tool_action")
        if task is None:
            return {"state": "idle", "reason": "no_claimable_tool_action"}
        task_id, lease_token = task["id"], task["lease_token"]
        try:
            authorized = self.gateway.authorize_task(task_id, lease_token)
        except AuthorizationDenied as exc:
            # The gateway emits a redacted denial event. Do not retry a malformed
            # or substituted action automatically, and never consume its approval.
            try:
                self.store.fail_task(task_id, lease_token, "authorization_denied", retryable=False)
            except Exception:
                pass
            return {"state": "blocked", "task_id": task_id, "reason": "authorization_denied"}

        # begin_execution revalidates lease, policy, action digest, approval and
        # cancellation immediately before any possible worker invocation. Current
        # policy intentionally returns blocked because host-enforced scoped egress
        # and a real isolated runtime are not verified in this deployment.
        gate = self.gateway.begin_execution(authorized["execution_id"],
                                            task_id=task_id, lease_token=lease_token)
        if gate.get("state") != "running":
            return {"state": gate.get("state", "blocked"), "task_id": task_id,
                    "execution_id": authorized["execution_id"],
                    "reason": gate.get("reason", "execution_boundary_unavailable")}

        # Defensive future path: a gateway may only return running after it has
        # verified a trusted boundary. Network actions still require an explicit
        # scoped-egress integration, so never pass them to a networkless worker.
        if self.supervisor is None:
            self.gateway.fail_execution(authorized["execution_id"], task_id=task_id,
                                        lease_token=lease_token, error_code="supervisor_unavailable")
            return {"state": "failed", "task_id": task_id, "reason": "supervisor_unavailable"}
        try:
            payload = task["input"]
            self.supervisor.run(payload, execution_id=authorized["execution_id"], network_required=True)
        except (SupervisorError, ValueError) as exc:
            self.gateway.fail_execution(authorized["execution_id"], task_id=task_id,
                                        lease_token=lease_token, error_code="worker_boundary_unavailable")
            return {"state": "blocked", "task_id": task_id, "reason": "worker_boundary_unavailable"}
        # Network-capable tool results must not be committed until a trusted
        # evidence adapter persists a request/response record matching action ID.
        self.gateway.fail_execution(authorized["execution_id"], task_id=task_id,
                                    lease_token=lease_token, error_code="evidence_adapter_unavailable")
        return {"state": "failed", "task_id": task_id, "reason": "evidence_adapter_unavailable"}
