from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import tempfile
import threading
import time
import uuid
from typing import Any

SCHEMA_VERSION = "2.0"


class ConcurrentStateWriteError(RuntimeError):
    """Raised when a stale blackboard would overwrite newer persisted state."""

CLAIM_STATUSES = {
    "observed", "hypothesized", "pending_verification", "verified",
    "contradicted", "inconclusive", "stale",
}
INTENT_STATUSES = {"open", "running", "complete", "failed", "blocked", "cancelled"}
TODO_STATUSES = {"pending", "running", "complete", "failed", "blocked", "cancelled"}
EDGE_RELATIONS = {
    "supports_intent", "yields_fact", "derived_from", "contradicts", "proves",
    "spawns", "anchors", "supports_claim", "contradicts_claim", "depends_on",
}


def _now() -> float:
    return time.time()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class Blackboard:
    """Durable per-assessment reasoning graph with conservative schema migration.

    Facts, claims, intents, todos, traces, and graph edges are explicit records.
    Model-generated claims remain unverified unless a deterministic verifier or
    human reviewer explicitly changes their status.
    """

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self._lock = threading.RLock()
        self._initial_save_required = not self.path.exists()
        self.data = self._empty_data()
        if self.path.exists():
            self.data = self._load_existing()
        try:
            self._persisted_revision = int(self.data.get("revision", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Blackboard revision must be an integer") from exc
        self._migrate()

    @staticmethod
    def _empty_data():
        return {
            "schema_version": SCHEMA_VERSION,
            "revision": 0,
            "facts": [],
            "claims": [],
            "intents": [],
            "hints": [],
            "edges": [],
            "completed_tests": [],
            "test_statuses": {},
            "todos": [],
            "traces": [],
            "assets": [],
            "assessment": {"status": "active", "created_ts": _now(), "updated_ts": _now()},
        }

    def _load_existing(self):
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # Never silently overwrite a corrupt state file. Preserve it for review.
            raise ValueError(f"Unable to load blackboard {self.path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ValueError(f"Blackboard root must be an object: {self.path}")
        version = str(loaded.get("schema_version", "1.0"))
        def version_tuple(value):
            try:
                return tuple(int(part) for part in value.split("."))
            except ValueError as exc:
                raise ValueError(f"Unsupported blackboard schema version {value!r}") from exc
        if version_tuple(version) > version_tuple(SCHEMA_VERSION):
            raise ValueError(f"Blackboard schema {version} is newer than supported schema {SCHEMA_VERSION}; refusing downgrade")
        return loaded

    def _migrate(self):
        before = _canonical(self.data)
        defaults = self._empty_data()
        for key, value in defaults.items():
            self.data.setdefault(key, value)
        # Normalize old schema records without deleting fields or history.
        for fact in self.data.get("facts", []):
            fact.setdefault("provenance", {"kind": "legacy", "source": fact.get("test_id", "unknown")})
            fact.setdefault("verification_status", "observed")
            fact.setdefault("version", 1)
        for intent in self.data.get("intents", []):
            intent.setdefault("attempts", 0)
            intent.setdefault("created_ts", intent.get("ts", _now()))
            intent.setdefault("updated_ts", intent.get("ts", _now()))
        self.data["schema_version"] = SCHEMA_VERSION
        validation = self.validate_graph()
        if not validation["valid"]:
            raise ValueError("Blackboard graph integrity validation failed: " + "; ".join(validation["errors"][:10]))
        if self._initial_save_required or _canonical(self.data) != before:
            self.save()

    def save(self):
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            lock_path = self.path.with_name(self.path.name + ".lock")
            lock_flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                lock_flags |= os.O_NOFOLLOW
            lock_fd = os.open(lock_path, lock_flags, 0o600)
            try:
                os.fchmod(lock_fd, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                disk_revision = 0
                if self.path.exists():
                    try:
                        disk_data = json.loads(self.path.read_text(encoding="utf-8"))
                        if not isinstance(disk_data, dict):
                            raise ValueError("Blackboard root must be an object")
                        disk_revision = int(disk_data.get("revision", 0))
                    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                        raise ValueError(f"Unable to verify current blackboard revision: {exc}") from exc
                if disk_revision != self._persisted_revision:
                    raise ConcurrentStateWriteError(
                        f"Blackboard changed on disk (loaded revision {self._persisted_revision}, "
                        f"current revision {disk_revision}); reload and reconcile before writing"
                    )
                new_revision = disk_revision + 1
                self.data["revision"] = new_revision
                self.data.setdefault("assessment", {})["updated_ts"] = _now()
                payload = json.dumps(self.data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
                fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temp_name, self.path)
                    try:
                        dir_fd = os.open(self.path.parent, os.O_RDONLY)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    except OSError:
                        pass
                    self._persisted_revision = new_revision
                    self._initial_save_required = False
                except Exception:
                    try:
                        os.unlink(temp_name)
                    except OSError:
                        pass
                    raise
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)

    def add_hint(self, text, *, source="operator"):
        with self._lock:
            item = {"id": _id("h"), "text": str(text)[:2000], "source": str(source)[:100], "ts": _now()}
            self.data["hints"].append(item)
            self.save()
            return item["id"]

    def add_fact(self, test_id, description, evidence_id=None, details=None, confidence="medium", *, provenance=None,
                 verification_status="observed", asset_id=None):
        if verification_status not in CLAIM_STATUSES:
            raise ValueError(f"Unsupported fact verification status: {verification_status}")
        record = {
            "test_id": str(test_id), "description": str(description)[:1000],
            "evidence_id": evidence_id, "details": details or {}, "confidence": confidence,
            "provenance": provenance or {"kind": "test", "source": str(test_id)},
            "verification_status": verification_status, "asset_id": asset_id,
        }
        fid = "f-" + hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()[:12]
        with self._lock:
            if not any(f.get("id") == fid for f in self.data["facts"]):
                self.data["facts"].append({"id": fid, **record, "version": 1, "ts": _now()})
            self.save()
            return fid

    def add_claim(self, text, *, claim_type="security_observation", asset_id=None, supporting_fact_ids=None,
                  evidence_ids=None, contradictory_claim_ids=None, status="hypothesized", provenance=None,
                  confidence="heuristic", rationale="", limitations=None, related_actions=None):
        if status not in CLAIM_STATUSES:
            raise ValueError(f"Unsupported claim status: {status}")
        if status == "verified":
            raise ValueError("Claims must be created unverified; use update_claim_status with reviewer and evidence")
        support = sorted(set(supporting_fact_ids or []))
        evidence = sorted(set(evidence_ids or []))
        contradictions = sorted(set(contradictory_claim_ids or []))
        known_facts = {x.get("id") for x in self.data.get("facts", [])}
        known_claims = {x.get("id") for x in self.data.get("claims", [])}
        missing_facts = set(support) - known_facts
        missing_claims = set(contradictions) - known_claims
        if missing_facts:
            raise ValueError("Claim references unknown facts: " + ", ".join(sorted(missing_facts)))
        if missing_claims:
            raise ValueError("Claim references unknown contradictory claims: " + ", ".join(sorted(missing_claims)))
        record = {
            "text": str(text)[:2000], "claim_type": str(claim_type)[:100], "asset_id": asset_id,
            "supporting_fact_ids": support, "evidence_ids": evidence,
            "contradictory_claim_ids": contradictions, "status": status,
            "provenance": provenance or {"kind": "agent", "source": "unspecified"},
            "confidence": str(confidence)[:100], "confidence_rationale": str(rationale)[:1000],
            "limitations": [str(x)[:500] for x in (limitations or [])[:30]],
            "related_actions": list(related_actions or [])[:100],
        }
        claim_id = "cl-" + hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()[:12]
        with self._lock:
            existing = next((x for x in self.data["claims"] if x.get("id") == claim_id), None)
            if existing:
                return claim_id
            now = _now()
            self.data["claims"].append({"id": claim_id, **record, "version": 1, "created_ts": now, "updated_ts": now})
            for fact_id in support:
                self.add_edge(fact_id, claim_id, "supports_claim")
            for other_id in contradictions:
                self.add_edge(other_id, claim_id, "contradicts_claim")
            self.save()
            return claim_id

    def update_claim_status(self, claim_id, status, *, reviewer=None, rationale="", evidence_ids=None):
        if status not in CLAIM_STATUSES:
            raise ValueError(f"Unsupported claim status: {status}")
        if status == "verified" and (not reviewer or not evidence_ids):
            raise ValueError("Verified status requires an explicit reviewer/verifier and supporting evidence IDs")
        with self._lock:
            claim = next((x for x in self.data["claims"] if x.get("id") == claim_id), None)
            if claim is None:
                raise KeyError(f"Unknown claim: {claim_id}")
            old_status = claim["status"]
            claim["status"] = status
            claim["version"] = int(claim.get("version", 1)) + 1
            claim["updated_ts"] = _now()
            claim.setdefault("status_history", []).append({
                "from": old_status, "to": status, "reviewer": reviewer or "system",
                "rationale": str(rationale)[:1000], "evidence_ids": list(evidence_ids or []), "ts": _now(),
            })
            if evidence_ids:
                claim["evidence_ids"] = sorted(set(claim.get("evidence_ids", []) + list(evidence_ids)))
            self.save()
            return claim

    def create_intent(self, test_id, reason, source_fact_ids=None, *, asset_id=None, prerequisites=None):
        source_fact_ids = list(dict.fromkeys(source_fact_ids or []))
        known_fact_ids = {x.get("id") for x in self.data.get("facts", [])}
        missing_facts = set(source_fact_ids) - known_fact_ids
        if missing_facts:
            raise ValueError("Intent references unknown source facts: " + ", ".join(sorted(missing_facts)))
        with self._lock:
            for it in self.data["intents"]:
                if it["test_id"] == test_id and it["status"] in ("open", "running"):
                    return it["id"]
            iid = _id("i")
            now = _now()
            item = {"id": iid, "test_id": str(test_id), "reason": str(reason)[:500],
                    "source_fact_ids": source_fact_ids, "asset_id": asset_id,
                    "prerequisites": prerequisites or [], "status": "open", "attempts": 0,
                    "created_ts": now, "updated_ts": now, "ts": now, "version": 1}
            self.data["intents"].append(item)
            for fact_id in item["source_fact_ids"]:
                self.add_edge(fact_id, iid, "derived_from")
            self.save()
            return iid

    def set_intent_status(self, iid, status, result=None):
        if status not in INTENT_STATUSES:
            raise ValueError(f"Unsupported intent status: {status}")
        with self._lock:
            for it in self.data["intents"]:
                if it["id"] == iid:
                    old = it["status"]
                    it["status"] = status
                    it["version"] = int(it.get("version", 1)) + 1
                    it["updated_ts"] = _now()
                    it.setdefault("status_history", []).append({"from": old, "to": status, "ts": _now()})
                    if result is not None:
                        it["result"] = result
                    if status == "running":
                        it["attempts"] = int(it.get("attempts", 0)) + 1
                    if status in ("complete", "failed", "blocked", "cancelled"):
                        it["finished_ts"] = _now()
                    if status == "complete" and it["test_id"] not in self.data["completed_tests"]:
                        self.data["completed_tests"].append(it["test_id"])
                    self.save()
                    return it
            raise KeyError(f"Unknown intent: {iid}")

    def set_test_status(self, test_id, status, *, reason="", result=None):
        allowed = {"pending", "running", "executed", "failed", "blocked", "deferred", "cancelled", "stale", "review_only"}
        if status not in allowed:
            raise ValueError(f"Unsupported test status: {status}")
        with self._lock:
            current = self.data.setdefault("test_statuses", {}).get(test_id, {})
            history = list(current.get("history", []))
            history.append({"from": current.get("status"), "to": status, "reason": str(reason)[:1000], "ts": _now()})
            record = {"status": status, "reason": str(reason)[:1000], "updated_ts": _now(), "history": history[-100:]}
            if result is not None:
                record["result"] = result
            self.data["test_statuses"][str(test_id)] = record
            if status == "executed" and test_id not in self.data["completed_tests"]:
                self.data["completed_tests"].append(test_id)
            elif status != "executed" and test_id in self.data["completed_tests"]:
                # Legacy completed_tests remains a successful-execution list only.
                self.data["completed_tests"].remove(test_id)
            self.save()
            return record

    def open_intents(self):
        return [i for i in self.data["intents"] if i["status"] == "open"]

    def completed(self, test_id):
        return test_id in self.data["completed_tests"]

    def add_edge(self, source_id, target_id, relation):
        if relation not in EDGE_RELATIONS:
            raise ValueError(f"Unsupported graph relation: {relation}")
        with self._lock:
            node_ids = {x.get("id") for key in ("facts", "claims", "intents", "todos", "assets", "hints", "traces")
                        for x in self.data.get(key, [])}
            if str(source_id) not in node_ids or str(target_id) not in node_ids:
                raise ValueError("Graph edges must reference existing nodes")
            edge = {"source_id": str(source_id), "target_id": str(target_id), "relation": relation}
            if edge not in self.data["edges"]:
                self.data["edges"].append(edge)
                self.save()
            return edge

    def add_asset(self, canonical_id, asset_type, *, value, scope_status="in_scope", provenance=None, attributes=None):
        if scope_status not in {"in_scope", "out_of_scope", "unknown"}:
            raise ValueError("scope_status must be in_scope, out_of_scope, or unknown")
        key = hashlib.sha256(_canonical([canonical_id, asset_type, value]).encode("utf-8")).hexdigest()[:16]
        with self._lock:
            existing = next((a for a in self.data["assets"] if a.get("id") == "as-" + key), None)
            if existing:
                # Preserve canonical first-seen values while retaining later attributes
                # and explicit conflicts instead of silently overwriting provenance.
                incoming_attributes = attributes or {}
                sighting = {"ts": _now(), "provenance": provenance or {"kind": "unspecified"},
                            "scope_status": scope_status, "attributes": incoming_attributes}
                existing.setdefault("sightings", []).append(sighting)
                existing["last_seen_ts"] = sighting["ts"]
                conflicts = existing.setdefault("attribute_conflicts", {})
                original_attributes = existing.setdefault("attributes", {})
                for attr_key, attr_value in incoming_attributes.items():
                    if attr_key in original_attributes and original_attributes[attr_key] != attr_value:
                        conflict = conflicts.setdefault(str(attr_key), {"initial": original_attributes[attr_key], "observed": []})
                        if attr_value not in conflict["observed"]:
                            conflict["observed"].append(attr_value)
                    elif attr_key not in original_attributes:
                        original_attributes[attr_key] = attr_value
                if existing.get("scope_status") != scope_status:
                    existing.setdefault("scope_conflicts", [])
                    conflict = {"initial": existing.get("scope_status"), "observed": scope_status}
                    if conflict not in existing["scope_conflicts"]:
                        existing["scope_conflicts"].append(conflict)
                self.save()
                return existing["id"]
            now = _now()
            item = {"id": "as-" + key, "canonical_id": str(canonical_id)[:500], "asset_type": str(asset_type)[:100],
                    "value": str(value)[:2000], "scope_status": scope_status,
                    "provenance": provenance or {"kind": "unspecified"}, "attributes": attributes or {},
                    "first_seen_ts": now, "last_seen_ts": now, "sightings": []}
            self.data["assets"].append(item)
            self.save()
            return item["id"]

    def add_todo(self, title, depends_on=None, completion_criterion="", test_id=None):
        dependencies = list(dict.fromkeys(depends_on or []))
        with self._lock:
            known = {x["id"] for x in self.data["todos"]}
            missing = set(dependencies) - known
            if missing:
                raise ValueError("Unknown todo dependencies: " + ", ".join(sorted(missing)))
            tid = _id("td")
            item = {"id": tid, "title": str(title)[:500], "depends_on": dependencies,
                    "completion_criterion": str(completion_criterion)[:500], "test_id": test_id,
                    "status": "pending", "ts": _now(), "version": 1}
            self.data["todos"].append(item)
            if self._todo_has_cycle():
                self.data["todos"].pop()
                raise ValueError("Todo dependency would create a cycle")
            self.save()
            return tid

    def _todo_has_cycle(self):
        graph = {x["id"]: x.get("depends_on", []) for x in self.data["todos"]}
        visiting, visited = set(), set()
        def visit(node):
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            for dep in graph.get(node, []):
                if visit(dep):
                    return True
            visiting.remove(node)
            visited.add(node)
            return False
        return any(visit(node) for node in graph)

    def update_todo(self, todo_id, status, result=None):
        if status not in TODO_STATUSES:
            raise ValueError(f"Unsupported todo status: {status}")
        with self._lock:
            for item in self.data["todos"]:
                if item["id"] == todo_id:
                    item["status"] = status
                    item["version"] = int(item.get("version", 1)) + 1
                    item["updated_ts"] = _now()
                    if result is not None:
                        item["result"] = result
                    self.save()
                    return item
            raise KeyError(f"Unknown todo: {todo_id}")

    def ready_todos(self):
        completed = {x["id"] for x in self.data["todos"] if x["status"] == "complete"}
        return [x for x in self.data["todos"] if x["status"] == "pending" and set(x["depends_on"]).issubset(completed)]

    def add_trace(self, *, intent_id=None, test_id=None, worker_id="local", event_type="observation", summary="",
                  asset_id=None, evidence_ids=None, details=None, ts=None):
        with self._lock:
            item = {"id": _id("tr"), "intent_id": intent_id, "test_id": test_id,
                    "worker_id": str(worker_id)[:100], "event_type": str(event_type)[:100],
                    "summary": str(summary)[:1000], "asset_id": asset_id,
                    "evidence_ids": list(evidence_ids or [])[:100], "details": details or {}, "ts": ts or _now()}
            self.data["traces"].append(item)
            # Keep persistent context bounded; full evidence remains in evidence files.
            if len(self.data["traces"]) > 5000:
                self.data["traces"] = self.data["traces"][-5000:]
            self.save()
            return item["id"]

    def search_traces(self, query, *, asset_id=None, test_id=None, exclude_intent_id=None, limit=10):
        terms = [x.casefold() for x in str(query).split() if x.strip()]
        limit = max(1, min(int(limit), 100))
        matches = []
        for item in reversed(self.data.get("traces", [])):
            if exclude_intent_id and item.get("intent_id") == exclude_intent_id:
                continue
            if asset_id and item.get("asset_id") != asset_id:
                continue
            if test_id and item.get("test_id") != test_id:
                continue
            haystack = _canonical([item.get("summary"), item.get("details"), item.get("event_type"), item.get("test_id")]).casefold()
            if terms and not all(term in haystack for term in terms):
                continue
            matches.append(item)
            if len(matches) >= limit:
                break
        return matches

    def validate_graph(self):
        node_ids = {x.get("id") for key in ("facts", "claims", "intents", "todos", "assets", "hints", "traces") for x in self.data.get(key, [])}
        errors = []
        all_ids = [x.get("id") for key in ("facts", "claims", "intents", "todos", "assets", "hints", "traces")
                   for x in self.data.get(key, []) if x.get("id") is not None]
        seen_ids = set()
        for node_id in all_ids:
            if node_id in seen_ids:
                errors.append(f"duplicate graph node id: {node_id}")
            seen_ids.add(node_id)
        for edge in self.data.get("edges", []):
            if edge.get("source_id") not in node_ids:
                errors.append(f"edge source missing: {edge.get('source_id')}")
            if edge.get("target_id") not in node_ids:
                errors.append(f"edge target missing: {edge.get('target_id')}")
            if edge.get("relation") not in EDGE_RELATIONS:
                errors.append(f"unsupported edge relation: {edge.get('relation')}")
        fact_ids = {x.get("id") for x in self.data.get("facts", [])}
        claim_ids = {x.get("id") for x in self.data.get("claims", [])}
        for claim in self.data.get("claims", []):
            if claim.get("status") not in CLAIM_STATUSES:
                errors.append(f"claim {claim.get('id')} has unsupported status {claim.get('status')}")
            for fact_id in claim.get("supporting_fact_ids", []):
                if fact_id not in fact_ids:
                    errors.append(f"claim {claim.get('id')} references missing fact {fact_id}")
            for other_id in claim.get("contradictory_claim_ids", []):
                if other_id not in claim_ids:
                    errors.append(f"claim {claim.get('id')} references missing contradictory claim {other_id}")
        for intent in self.data.get("intents", []):
            if intent.get("status") not in INTENT_STATUSES:
                errors.append(f"intent {intent.get('id')} has unsupported status {intent.get('status')}")
        for todo in self.data.get("todos", []):
            if todo.get("status") not in TODO_STATUSES:
                errors.append(f"todo {todo.get('id')} has unsupported status {todo.get('status')}")
            missing_dependencies = set(todo.get("depends_on", [])) - {x.get("id") for x in self.data.get("todos", [])}
            if missing_dependencies:
                errors.append(f"todo {todo.get('id')} references missing dependencies: {', '.join(sorted(missing_dependencies))}")
        return {"valid": not errors, "errors": errors, "node_count": len(node_ids), "edge_count": len(self.data.get("edges", []))}

    def summary(self):
        return {
            "facts": [{"id": f["id"], "test_id": f["test_id"], "description": f["description"],
                       "evidence_id": f.get("evidence_id"), "confidence": f.get("confidence"),
                       "verification_status": f.get("verification_status"), "asset_id": f.get("asset_id")}
                      for f in self.data["facts"][-60:]],
            "claims": [{"id": c["id"], "text": c["text"], "status": c["status"], "confidence": c["confidence"],
                        "asset_id": c.get("asset_id"), "evidence_ids": c.get("evidence_ids", [])}
                       for c in self.data.get("claims", [])[-60:]],
            "open_intents": [{"id": i["id"], "test_id": i["test_id"], "reason": i["reason"], "status": i["status"]}
                             for i in self.open_intents()],
            "completed_tests": self.data["completed_tests"],
            "test_statuses": {k: {"status": v.get("status"), "reason": v.get("reason")}
                              for k, v in self.data.get("test_statuses", {}).items()},
            "hints": self.data["hints"][-10:],
            "todos": [{"id": t["id"], "title": t["title"], "status": t["status"], "depends_on": t.get("depends_on", [])}
                      for t in self.data["todos"][-40:]],
            "recent_traces": [{"id": t["id"], "intent_id": t.get("intent_id"), "test_id": t.get("test_id"),
                               "event_type": t.get("event_type"), "summary": t.get("summary"), "asset_id": t.get("asset_id")}
                              for t in self.data.get("traces", [])[-20:]],
            "assessment": self.data.get("assessment", {}),
        }
