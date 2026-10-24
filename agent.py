#!/usr/bin/env python3
from __future__ import annotations
import argparse, getpass, json, os, pathlib, re, sys
from appsec_agent import __version__
from appsec_agent.policy import load_policy, validate_url
from appsec_agent.engine import run


def _current_operator_id():
    """Resolve identity from the OS UID on POSIX, not spoofable USER env vars."""
    if hasattr(os, "getuid"):
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    return getpass.getuser()


def main():
    ap=argparse.ArgumentParser(prog="artemis", description="ARTEMIS: Autonomous Application Security Testing Platform")
    ap.add_argument("--version", action="version", version=f"ARTEMIS {__version__}")
    ap.add_argument("--policy",default="policy.json")
    ap.add_argument("--run-id",default="run-001")
    ap.add_argument("--openapi")
    ap.add_argument("--scenarios")
    ap.add_argument("--workflow")
    ap.add_argument("--catalog",default=str(pathlib.Path(__file__).resolve().parent/"test_catalog.json"))
    ap.add_argument("--sarif",action="append",default=[])
    ap.add_argument("--sarif-only",action="store_true",help="Import SARIF findings without contacting the target")
    ap.add_argument("--provider",choices=["offline","openai","anthropic"],default=None)
    ap.add_argument("--dry-run",action="store_true")
    ap.add_argument("--max-iterations",type=int,default=None)
    ap.add_argument("--hint",action="append",default=[],help="Add a planner hint for this run; may be repeated")
    ap.add_argument("--validate-catalog",action="store_true",help="Validate catalog schema and exit without network traffic")
    ap.add_argument("--validate-state",nargs="?",const="runs/run-001/blackboard.json",default=None,
                    help="Validate a saved blackboard graph and exit (optional path; defaults to runs/run-001/blackboard.json)")
    ap.add_argument("--verify-traffic",nargs="?",const="runs/run-001",default=None,
                    help="Verify traffic/evidence/finding links and manifest for a run directory")
    ap.add_argument("--benchmark-compare", default=None,
                    help="Compare a current benchmark report to a named baseline using explicit thresholds in a JSON file")
    ap.add_argument("--runtime-action", choices=["create-job", "add-task", "claim", "start", "heartbeat", "complete", "fail", "cancel", "recover", "status", "events", "approval-request", "approval-decide", "approval-consume", "approval-list", "approval-revoke", "audit-verify", "serve-api", "dispatch-once"],
                    help="Operate the transactional local runtime queue; this does not execute security tools")
    ap.add_argument("--runtime-db", default="runs/runtime.sqlite3", help="SQLite runtime database path")
    ap.add_argument("--job-id")
    ap.add_argument("--task-id")
    ap.add_argument("--worker-id")
    ap.add_argument("--lease-token")
    ap.add_argument("--lease-seconds", type=int, default=60)
    ap.add_argument("--policy-digest", help="Optional assertion that must equal the digest computed from the validated --policy file")
    ap.add_argument("--idempotency-key")
    ap.add_argument("--task-key")
    ap.add_argument("--task-type")
    ap.add_argument("--task-input", default="{}", help="JSON object for task input")
    ap.add_argument("--depends-on", action="append", default=[], help="Task ID dependency; may be repeated")
    ap.add_argument("--priority", type=int, default=0)
    ap.add_argument("--max-attempts", type=int, default=2)
    ap.add_argument("--task-result", default="{}", help="JSON object for task result")
    ap.add_argument("--task-error", default="Task failed")
    ap.add_argument("--non-retryable", action="store_true")
    ap.add_argument("--event-after", type=int, default=0)
    ap.add_argument("--approval-id")
    ap.add_argument("--operator-id", help="Local operator identifier for an approval request or decision")
    ap.add_argument("--approval-decision", choices=["approve", "reject"])
    ap.add_argument("--approval-reason", default="")
    ap.add_argument("--approval-ttl", type=int, default=900)
    ap.add_argument("--api-host", default="127.0.0.1", help="Operator API bind address; only loopback is supported")
    ap.add_argument("--api-port", type=int, default=8765, help="Operator API port")
    ap.add_argument("--api-credentials-env", default="ARTEMIS_OPERATOR_CREDENTIALS_JSON",
                    help="Environment variable containing server-side JSON token-to-identity mapping")
    ap.add_argument("--action-target", help="Exact target string bound to an approval")
    ap.add_argument("--tool-name", help="Registered tool identifier bound to an approval")
    ap.add_argument("--action-parameters", default="{}", help="Exact JSON object parameters bound to an approval")
    args=ap.parse_args()
    if args.benchmark_compare is not None:
        from appsec_agent.benchmark import compare_to_baseline
        compare_path = pathlib.Path(args.benchmark_compare)
        if compare_path.is_symlink() or not compare_path.is_file() or compare_path.stat().st_size > 1_000_000:
            ap.error("--benchmark-compare must be a regular non-symlink JSON file no larger than 1 MB")
        try:
            comparison_input = json.loads(compare_path.read_text(encoding="utf-8"))
            result = compare_to_baseline(comparison_input["current"], comparison_input["baseline"], comparison_input["thresholds"])
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            ap.error("invalid benchmark comparison input: " + type(exc).__name__)
        print(json.dumps(result, indent=2, allow_nan=False))
        if not result["passed"]:
            raise SystemExit(2)
        return
    if args.verify_traffic is not None:
        from appsec_agent.evidence import EvidenceStore
        result = EvidenceStore(args.verify_traffic).verify_traffic()
        print(json.dumps({"path": args.verify_traffic, **result}, indent=2))
        if not result.get("valid"):
            raise SystemExit(2)
        return
    if args.runtime_action:
        from appsec_agent.runtime_store import RuntimeStore, policy_digest
        try:
            if args.operator_id and args.operator_id != _current_operator_id():
                ap.error("--operator-id must match the current operating-system user; impersonation is not allowed")
            operator_id = _current_operator_id()
            runtime = RuntimeStore(args.runtime_db)
            if args.runtime_action == "dispatch-once":
                if not args.worker_id:
                    ap.error("dispatch-once requires --worker-id")
                from appsec_agent.dispatcher import QueueDispatcher
                from appsec_agent.worker_supervisor import ContainerWorkerSupervisor, SupervisorError
                policy = load_policy(args.policy)
                digest = policy_digest(policy)
                if args.policy_digest and args.policy_digest != digest:
                    ap.error("--policy-digest does not match the canonical validated policy file")
                supervisor = None
                image = os.environ.get("ARTEMIS_WORKER_IMAGE")
                entrypoint_raw = os.environ.get("ARTEMIS_WORKER_ENTRYPOINT_JSON")
                if image and entrypoint_raw:
                    try:
                        entrypoint = json.loads(entrypoint_raw)
                    except json.JSONDecodeError:
                        ap.error("ARTEMIS_WORKER_ENTRYPOINT_JSON must be a JSON array")
                    if not isinstance(entrypoint, list) or not entrypoint or any(not isinstance(x, str) for x in entrypoint):
                        ap.error("ARTEMIS_WORKER_ENTRYPOINT_JSON must be a non-empty string array")
                    try:
                        supervisor = ContainerWorkerSupervisor(image=image, entrypoint=entrypoint)
                    except (ValueError, SupervisorError) as exc:
                        ap.error(f"worker supervisor configuration rejected: {exc}")
                dispatcher = QueueDispatcher(runtime, policy, supervisor=supervisor)
                result = dispatcher.dispatch_once(args.worker_id, lease_seconds=args.lease_seconds, job_id=args.job_id)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 0
            elif args.runtime_action == "serve-api":
                from appsec_agent.operator_api import OperatorControlServer
                credentials_raw = os.environ.get(args.api_credentials_env)
                if not credentials_raw:
                    ap.error(f"serve-api requires credentials in environment variable {args.api_credentials_env}")
                try:
                    credentials = json.loads(credentials_raw)
                except json.JSONDecodeError:
                    ap.error("operator API credentials environment variable must contain valid JSON")
                server = OperatorControlServer((args.api_host, args.api_port), runtime_db=args.runtime_db,
                                               credentials=credentials, policy=load_policy(args.policy))
                print(json.dumps({"status": "listening", "host": args.api_host, "port": server.server_address[1]}))
                try:
                    server.serve_forever()
                finally:
                    server.server_close()
                return 0
            elif args.runtime_action == "create-job":
                policy_digest_value = policy_digest(load_policy(args.policy))
                if args.policy_digest and args.policy_digest != policy_digest_value:
                    ap.error("--policy-digest does not match the canonical validated policy file")
                result = runtime.create_job(policy_digest=policy_digest_value, idempotency_key=args.idempotency_key)
            elif args.runtime_action == "add-task":
                if not args.job_id or not args.task_key or not args.task_type:
                    ap.error("--runtime-action add-task requires --job-id, --task-key, and --task-type")
                task_input = json.loads(args.task_input)
                if not isinstance(task_input, dict): ap.error("--task-input must be a JSON object")
                result = runtime.add_task(args.job_id, args.task_key, args.task_type, input=task_input,
                                          dependencies=args.depends_on, priority=args.priority, max_attempts=args.max_attempts)
            elif args.runtime_action == "claim":
                if not args.worker_id: ap.error("--runtime-action claim requires --worker-id")
                policy_digest_value = policy_digest(load_policy(args.policy))
                if args.policy_digest and args.policy_digest != policy_digest_value:
                    ap.error("--policy-digest does not match the canonical validated policy file")
                result = runtime.claim_next(args.worker_id, expected_policy_digest=policy_digest_value,
                                            lease_seconds=args.lease_seconds, job_id=args.job_id)
            elif args.runtime_action == "start":
                if not args.task_id or not args.lease_token: ap.error("start requires --task-id and --lease-token")
                result = runtime.start_task(args.task_id, args.lease_token)
            elif args.runtime_action == "heartbeat":
                if not args.task_id or not args.lease_token: ap.error("heartbeat requires --task-id and --lease-token")
                result = {"lease_expires_at": runtime.heartbeat(args.task_id, args.lease_token, lease_seconds=args.lease_seconds)}
            elif args.runtime_action == "complete":
                if not args.task_id or not args.lease_token: ap.error("complete requires --task-id and --lease-token")
                task_result = json.loads(args.task_result)
                if not isinstance(task_result, dict): ap.error("--task-result must be a JSON object")
                result = runtime.complete_task(args.task_id, args.lease_token, result=task_result)
            elif args.runtime_action == "fail":
                if not args.task_id or not args.lease_token: ap.error("fail requires --task-id and --lease-token")
                result = runtime.fail_task(args.task_id, args.lease_token, args.task_error, retryable=not args.non_retryable)
            elif args.runtime_action == "cancel":
                if not args.job_id: ap.error("cancel requires --job-id")
                result = runtime.cancel_job(args.job_id)
            elif args.runtime_action == "recover":
                result = runtime.recover_expired()
            elif args.runtime_action == "status":
                if not args.job_id: ap.error("status requires --job-id")
                result = {"job": runtime.get_job(args.job_id), "tasks": runtime.list_tasks(args.job_id)}
            elif args.runtime_action == "approval-request":
                from appsec_agent.approval import ApprovalGateway
                if not args.job_id or not args.action_target or not args.tool_name:
                    ap.error("approval-request requires --job-id, --action-target, --tool-name, and --operator-id")
                params = json.loads(args.action_parameters)
                if not isinstance(params, dict): ap.error("--action-parameters must be a JSON object")
                policy = load_policy(args.policy)
                digest = policy_digest(policy)
                if args.policy_digest and args.policy_digest != digest:
                    ap.error("--policy-digest does not match the canonical validated policy file")
                result = ApprovalGateway(runtime, policy).request(job_id=args.job_id, target=args.action_target,
                    tool_name=args.tool_name, parameters=params, policy_digest=digest,
                    requested_by=operator_id, ttl_seconds=args.approval_ttl)
            elif args.runtime_action == "approval-decide":
                from appsec_agent.approval import ApprovalGateway
                if not args.approval_id or not args.approval_decision:
                    ap.error("approval-decide requires --approval-id, --operator-id, and --approval-decision")
                result = ApprovalGateway(runtime).decide(args.approval_id, approver_id=operator_id,
                    approve=args.approval_decision == "approve", reason=args.approval_reason)
            elif args.runtime_action == "approval-consume":
                from appsec_agent.approval import ApprovalGateway
                if not args.approval_id or not args.job_id or not args.action_target or not args.tool_name:
                    ap.error("approval-consume requires --approval-id, --job-id, --action-target, and --tool-name")
                params = json.loads(args.action_parameters)
                if not isinstance(params, dict): ap.error("--action-parameters must be a JSON object")
                policy = load_policy(args.policy)
                digest = policy_digest(policy)
                if args.policy_digest and args.policy_digest != digest:
                    ap.error("--policy-digest does not match the canonical validated policy file")
                result = ApprovalGateway(runtime, policy).consume(args.approval_id, job_id=args.job_id,
                    target=args.action_target, tool_name=args.tool_name, parameters=params, policy_digest=digest)
            elif args.runtime_action == "approval-list":
                from appsec_agent.approval import ApprovalGateway
                if not args.job_id: ap.error("approval-list requires --job-id")
                result = ApprovalGateway(runtime).list_for_job(args.job_id)
            elif args.runtime_action == "approval-revoke":
                from appsec_agent.approval import ApprovalGateway
                if not args.approval_id: ap.error("approval-revoke requires --approval-id and --operator-id")
                result = ApprovalGateway(runtime).revoke(args.approval_id, revoked_by=operator_id, reason=args.approval_reason)
            elif args.runtime_action == "audit-verify":
                result = runtime.verify_audit_chain()
                if not result.get("valid"):
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    raise SystemExit(2)
            else:
                if not args.job_id: ap.error("events requires --job-id")
                result = runtime.list_events(args.job_id, after_id=args.event_after)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        except (ValueError, KeyError, RuntimeError) as exc:
            ap.error(str(exc))
        return
    if args.validate_state is not None:
        from appsec_agent.blackboard import Blackboard
        state_path=pathlib.Path(args.validate_state)
        if not state_path.exists():
            ap.error(f"Blackboard state file does not exist: {state_path}")
        board=Blackboard(state_path)
        result=board.validate_graph()
        print(json.dumps({"path":str(state_path), **result},indent=2))
        if not result["valid"]:
            raise SystemExit(2)
        return
    provider=(args.provider or os.environ.get("AI_PROVIDER","offline")).lower()
    if args.validate_catalog:
        from pathlib import Path
        cat=json.loads(Path(args.catalog).read_text(encoding="utf-8"))
        ids=[x.get("id") for x in cat.get("runnable_tests",[])]
        if not ids or len(ids)!=len(set(ids)):
            ap.error("Catalog runnable_tests must have unique non-empty IDs")
        print(json.dumps({"valid":True,"runnable_test_count":len(ids),"framework_count":len(cat.get("frameworks",{}))},indent=2))
        return
    if args.sarif_only:
        if not args.sarif:
            ap.error("--sarif-only requires at least one --sarif file")
        from appsec_agent.evidence import EvidenceStore
        from appsec_agent.sarif import import_sarif
        from appsec_agent.report import build_coverage, write_report
        catalog=json.loads(pathlib.Path(args.catalog).read_text(encoding="utf-8"))
        run_id=re.sub(r"[^A-Za-z0-9_.-]","_",args.run_id)
        run_dir=pathlib.Path("runs")/run_id
        store=EvidenceStore(run_dir)
        count=import_sarif(args.sarif,store)
        findings=[]
        fp=run_dir/"findings.jsonl"
        if fp.exists():
            findings=[json.loads(line) for line in fp.read_text(encoding="utf-8").splitlines() if line.strip()]
        coverage=build_coverage(catalog,[],findings,[],test_statuses={})
        (run_dir/"coverage.json").write_text(json.dumps(coverage,indent=2)+"\n",encoding="utf-8")
        summary={"run_id":run_id,"target":None,"provider":"none","requests_used":0,"sarif_findings_imported":count,
                 "findings_count":len(findings),"note":"SARIF-only mode; no target requests sent."}
        (run_dir/"run_summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
        write_report(run_dir,summary,findings,coverage)
        print(json.dumps(summary,indent=2))
        return
    if provider not in ("offline","openai","anthropic"): ap.error("provider must be offline, openai, or anthropic")
    policy=load_policy(args.policy)
    if args.dry_run:
        targets=[]
        for path in policy.get("baseline_paths",["/"]):
            from urllib.parse import urljoin
            url=urljoin(policy["base_url"].rstrip("/")+"/",path.lstrip("/"))
            validate_url(policy,url,"GET",resolve_dns=False)
            targets.append(url)
        scenario_count=0
        if args.scenarios:
            from appsec_agent.scenarios import load_scenarios, validate_scenario
            for scenario in load_scenarios(args.scenarios):
                if scenario.get("enabled"):
                    validate_scenario(scenario,policy,check_dns=False)
                    scenario_count += 1
        print(json.dumps({"target":policy["base_url"],"targets":targets,"allowed_hosts":policy["allowed_hosts"],
            "allowed_methods":policy["allowed_methods"],"max_requests":policy["max_requests"],"provider":provider,
            "enabled_scenarios_validated":scenario_count,"network_requests":0,"enabled_tests":policy.get("enabled_tests",[])},indent=2))
        return
    if provider=="openai" and not os.environ.get("OPENAI_API_KEY"): ap.error("Set OPENAI_API_KEY or use --provider offline")
    if provider=="anthropic" and not os.environ.get("ANTHROPIC_API_KEY"): ap.error("Set ANTHROPIC_API_KEY or use --provider offline")
    run_id=re.sub(r"[^A-Za-z0-9_.-]","_",args.run_id)
    run_dir=pathlib.Path("runs")/run_id
    result=run(policy,run_dir,provider=provider,openapi_path=args.openapi,scenarios_path=args.scenarios,
               workflow_path=args.workflow,catalog_path=args.catalog,sarif_paths=args.sarif,max_iterations=args.max_iterations,
               hints=args.hint)
    print(json.dumps(result,indent=2))

if __name__=="__main__": main()
