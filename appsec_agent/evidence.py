from __future__ import annotations
import base64, hashlib, json, os, pathlib, re, stat, time, uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"(?i)\b(token|password|secret|session|api[_-]?key)\b([\"']?\s*[:=]\s*[\"']?)[^\"'\s,;]{4,}")
]
SENSITIVE_HEADERS = {"authorization","cookie","set-cookie","x-api-key","proxy-authorization"}
SENSITIVE_FIELD_RE = re.compile(r"(?i)(?:^|[_-])(password|passwd|secret|token|access[_-]?key|api[_-]?key|client[_-]?secret|authorization|cookie|session(?:id)?|refresh[_-]?token)(?:$|[_-])")
SENSITIVE_QUERY_NAMES = {"token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "key", "secret", "password", "passwd", "session", "sessionid", "authorization", "cookie"}


def redact_url(value):
    """Redact credential-like query parameters while preserving safe URL context."""
    try:
        parts = urlsplit(str(value))
        query = []
        for key, val in parse_qsl(parts.query, keep_blank_values=True):
            sensitive = key.lower().replace("-", "_") in SENSITIVE_QUERY_NAMES or bool(SENSITIVE_FIELD_RE.search(key))
            query.append((key, "[REDACTED]" if sensitive else val))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    except (ValueError, TypeError):
        return redact_text(value)


def redact_payload(value, key=""):
    """Recursively redact common secret-bearing structured fields."""
    if key and (key.lower() in SENSITIVE_QUERY_NAMES or bool(SENSITIVE_FIELD_RE.search(key))):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_payload(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_payload(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_body(raw):
    """Return a redacted evidence representation without retaining raw secret values."""
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Binary bodies may contain arbitrary data; do not persist them as raw base64.
        return b"[BINARY BODY OMITTED]", True
    try:
        parsed = json.loads(decoded)
    except (json.JSONDecodeError, ValueError):
        safe = redact_text(decoded)
        return safe.encode("utf-8"), safe != decoded
    safe_obj = redact_payload(parsed)
    safe = json.dumps(safe_obj, ensure_ascii=False, separators=(",", ":"))
    return safe.encode("utf-8"), safe != decoded


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def redact_text(value):
    s = str(value)
    # JSON bodies need key-aware redaction because regex-only handling can miss
    # underscore-separated names such as access_token or nested secret fields.
    if s.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(s)
            safe = redact_payload(parsed)
            return json.dumps(safe, ensure_ascii=False, separators=(",", ":"))
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    for i, pat in enumerate(SECRET_VALUE_PATTERNS):
        if i == 0: s = pat.sub("Bearer [REDACTED]", s)
        elif i == 1: s = pat.sub("[REDACTED_JWT]", s)
        else: s = pat.sub(r"\1\2[REDACTED]", s)
    return s

def redact_headers(headers):
    def sensitive(name):
        low=name.lower()
        return low in SENSITIVE_HEADERS or any(marker in low for marker in ("authorization","cookie","token","secret","api-key","apikey","password"))
    return {k: ("[REDACTED]" if sensitive(k) else redact_text(v)[:500]) for k, v in headers.items()}

def safe_observation(obs, max_chars=3000):
    """Produce model-safe data. Raw headers/body are deliberately removed."""
    out = {}
    for k, v in obs.items():
        if k.startswith("_") or k in ("raw_headers","raw_body","request_headers","cookies"):
            continue
        if k == "body_excerpt":
            out[k] = redact_text(str(v)[:max_chars])
        elif k == "headers":
            out[k] = redact_headers(v if isinstance(v, dict) else {})
        elif k == "url":
            out[k] = redact_url(v)
        else:
            out[k] = v
    return out

class EvidenceStore:
    def __init__(self, run_dir):
        self.run_dir = pathlib.Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try: os.chmod(self.run_dir, 0o700)
        except OSError: pass
        self.seq = 0
        self._traffic_by_evidence = {}
        self._traffic_by_id = {}
        evidence_path = self.run_dir / "evidence.jsonl"
        if evidence_path.exists():
            for line in evidence_path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                    evidence_id = item.get("evidence_id", "")
                    match = re.fullmatch(r"ev-(\d+)-[0-9a-f]{10}", evidence_id)
                    if match:
                        self.seq = max(self.seq, int(match.group(1)))
                    if item.get("traffic_id") and evidence_id:
                        self._traffic_by_evidence[evidence_id] = item["traffic_id"]
                except (json.JSONDecodeError, TypeError):
                    continue
        traffic_path = self.run_dir / "traffic.jsonl"
        if traffic_path.exists():
            for line in traffic_path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                    if item.get("traffic_id"):
                        self._traffic_by_id[item["traffic_id"]] = item
                except (json.JSONDecodeError, TypeError):
                    continue
        self._finding_keys = set()
        self._finding_count = 0
        findings_path = self.run_dir / "findings.jsonl"
        if findings_path.exists():
            for line in findings_path.read_text(encoding="utf-8").splitlines():
                try:
                    item=json.loads(line)
                    self._finding_keys.add(item.get("dedupe_key"))
                    self._finding_count += 1
                except Exception:
                    pass
        self._bootstrap_manifest()

    def _bootstrap_manifest(self):
        manifest = self.run_dir / "evidence_manifest.jsonl"
        if manifest.exists():
            return
        # Adopt existing legacy rows as the initial baseline without rewriting them.
        for path in sorted(self.run_dir.glob("*.jsonl")):
            if path.name == "evidence_manifest.jsonl":
                continue
            for line in path.read_bytes().splitlines():
                if line:
                    self._append_manifest_entry(path.name, sha256(line))

    def append(self, filename, record):
        # Evidence filenames are fixed basenames. Reject traversal and symlinks so a
        # crafted run directory cannot redirect evidence writes outside the run.
        if not isinstance(filename, str) or pathlib.Path(filename).name != filename or filename in {".", ".."}:
            raise ValueError("Evidence filename must be a simple basename")
        path = self.run_dir / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Evidence destination must be a regular file")
            serialized = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            with os.fdopen(fd, "ab") as stream:
                fd = -1
                stream.write(serialized + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        if filename != "evidence_manifest.jsonl":
            self._append_manifest_entry(filename, sha256(serialized))

    def _append_manifest_entry(self, filename, record_digest):
        """Append a chained integrity record for each persisted evidence row."""
        manifest = self.run_dir / "evidence_manifest.jsonl"
        previous = "0" * 64
        sequence = 1
        if manifest.exists():
            lines = manifest.read_text(encoding="utf-8").splitlines()
            if lines:
                try:
                    last = json.loads(lines[-1])
                    previous = last["entry_hash"]
                    sequence = int(last["sequence"]) + 1
                except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                    raise ValueError("Evidence manifest is malformed; refusing further writes") from exc
        entry = {"sequence": sequence, "filename": filename, "record_sha256": record_digest,
                 "previous_hash": previous, "timestamp": time.time()}
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        entry["entry_hash"] = sha256(canonical.encode("utf-8"))
        self._append_manifest_line(entry)

    def _append_manifest_line(self, entry):
        path = self.run_dir / "evidence_manifest.jsonl"
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "ab") as stream:
                fd = -1
                stream.write((json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)

    def verify_manifest(self):
        """Verify the hash chain and that every manifest row maps to a stored record."""
        path = self.run_dir / "evidence_manifest.jsonl"
        if not path.exists():
            return {"valid": False, "entries": 0, "errors": ["manifest_missing"]}
        errors, previous, sequence = [], "0" * 64, 0
        indexed_records = {}
        for file_path in sorted(self.run_dir.glob("*.jsonl")):
            if file_path.name == "evidence_manifest.jsonl":
                continue
            try:
                indexed_records[file_path.name] = [sha256(line) for line in file_path.read_bytes().splitlines() if line]
            except OSError:
                errors.append("record_file_unreadable:" + file_path.name)
        seen = {name: 0 for name in indexed_records}
        try:
            rows = path.read_text(encoding="utf-8").splitlines()
            for line_no, line in enumerate(rows, 1):
                try:
                    entry = json.loads(line)
                    entry_hash = entry.pop("entry_hash")
                    expected = sha256(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                    if entry_hash != expected: errors.append(f"entry_hash_mismatch:{line_no}")
                    if entry.get("previous_hash") != previous: errors.append(f"chain_mismatch:{line_no}")
                    if int(entry.get("sequence", -1)) != sequence + 1: errors.append(f"sequence_mismatch:{line_no}")
                    filename = entry.get("filename")
                    if filename not in indexed_records: errors.append(f"unknown_record_file:{line_no}")
                    else:
                        idx = seen[filename]
                        rows_for_file = indexed_records[filename]
                        if idx >= len(rows_for_file): errors.append(f"manifest_row_missing:{line_no}")
                        elif rows_for_file[idx] != entry.get("record_sha256"): errors.append(f"record_hash_mismatch:{line_no}")
                        seen[filename] = idx + 1
                    previous, sequence = entry_hash, sequence + 1
                except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                    errors.append(f"malformed_manifest_row:{line_no}")
        except OSError:
            return {"valid": False, "entries": 0, "errors": ["manifest_unreadable"]}
        for name, rows in indexed_records.items():
            if seen.get(name, 0) != len(rows): errors.append("unmanifested_records:" + name)
        return {"valid": not errors, "entries": sequence, "errors": errors}

    def export_bundle(self, destination):
        """Export a verified, redacted evidence bundle without changing source files."""
        import zipfile
        destination = pathlib.Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        integrity = self.verify_manifest()
        if not integrity["valid"]:
            raise ValueError("Cannot export evidence with an invalid manifest: " + ", ".join(integrity["errors"][:5]))
        files = [p for p in self.run_dir.iterdir() if p.is_file() and p.name in {
            "evidence.jsonl", "findings.jsonl", "events.jsonl", "evidence_manifest.jsonl",
            "verification_history.jsonl", "retest_history.jsonl", "traffic.jsonl"}]
        evidence_rows = []
        evidence_path = self.run_dir / "evidence.jsonl"
        if evidence_path.exists():
            for line in evidence_path.read_text(encoding="utf-8").splitlines():
                try: evidence_rows.append(json.loads(line))
                except json.JSONDecodeError: continue
        redacted = sum(1 for row in evidence_rows if row.get("response", {}).get("body_redacted"))
        export_manifest = {"schema_version": 1, "created_at": time.time(), "integrity": integrity,
                           "redaction_status": {"evidence_records": len(evidence_rows), "body_redacted_records": redacted,
                                                "all_records_redacted_before_persistence": True},
                           "files": {p.name: sha256(p.read_bytes()) for p in sorted(files)}}
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in sorted(files): archive.write(item, arcname=item.name)
            archive.writestr("export_manifest.json", json.dumps(export_manifest, sort_keys=True, indent=2))
        try: os.chmod(destination, 0o600)
        except OSError: pass
        return export_manifest
    def capture(self, request_record, status, response_headers, response_body, elapsed_ms, reason):
        self.seq += 1
        evidence_id = f"ev-{self.seq:05d}-{sha256(response_body)[:10]}"
        safe_body, body_redacted = redact_body(response_body)
        safe_request = redact_payload(request_record)
        if isinstance(safe_request, dict) and "url" in safe_request:
            safe_request["url"] = redact_url(safe_request["url"])
        if isinstance(safe_request, dict) and "body" in safe_request and isinstance(safe_request["body"], str):
            safe_request["body"] = redact_text(safe_request["body"])
        request_body = request_record.get("body") if isinstance(request_record, dict) else None
        if request_body is None and isinstance(request_record, dict):
            request_body = request_record.get("json")
        if isinstance(request_body, bytes):
            request_body_bytes = request_body
        elif request_body is None:
            request_body_bytes = b""
        elif isinstance(request_body, str):
            request_body_bytes = request_body.encode("utf-8", errors="replace")
        else:
            request_body_bytes = json.dumps(request_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        traffic_material = json.dumps({"evidence_id": evidence_id, "request": safe_request,
                                       "status": status, "response_sha256": sha256(response_body)},
                                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        traffic_id = f"tr-{self.seq:05d}-{sha256(traffic_material)[:12]}"
        timestamp = time.time()
        safe_response_headers = redact_headers(response_headers)
        cookie_attributes = []
        for header_name, header_value in response_headers.items():
            if str(header_name).lower() != "set-cookie":
                continue
            values = header_value if isinstance(header_value, (list, tuple)) else [header_value]
            for cookie_value in values:
                pieces = [piece.strip().lower() for piece in str(cookie_value).split(";")]
                cookie_attributes.append({"secure": "secure" in pieces,
                                          "httponly": "httponly" in pieces,
                                          "samesite": any(piece.startswith("samesite=") for piece in pieces)})
        traffic_record = {
            "traffic_id": traffic_id, "sequence": self.seq, "timestamp": timestamp,
            "evidence_id": evidence_id,
            "request": {"method": str(request_record.get("method", "GET")).upper() if isinstance(request_record, dict) else "GET",
                        "url": redact_url(request_record.get("url", "")) if isinstance(request_record, dict) else "",
                        "headers": redact_headers(request_record.get("headers", {}) if isinstance(request_record, dict) and isinstance(request_record.get("headers", {}), dict) else {}),
                        "body_sha256": sha256(request_body_bytes), "body_bytes": len(request_body_bytes)},
            "response": {"status": status, "headers": safe_response_headers,
                         "body_sha256": sha256(response_body), "stored_body_sha256": sha256(safe_body),
                         "body_bytes": len(response_body), "stored_body_bytes": len(safe_body),
                         "body_redacted": body_redacted, "elapsed_ms": elapsed_ms}
        }
        record = {
            "evidence_id": evidence_id, "traffic_id": traffic_id, "timestamp": timestamp,
            "reason": redact_text(reason)[:200], "request": safe_request,
            "response": {"status": status, "headers": safe_response_headers,
                         "cookie_attributes": cookie_attributes,
                         "body_base64": base64.b64encode(safe_body).decode(),
                         "body_sha256": sha256(response_body),
                         "stored_body_sha256": sha256(safe_body),
                         "bytes_captured": len(response_body), "bytes_stored": len(safe_body),
                         "body_redacted": body_redacted, "elapsed_ms": elapsed_ms}
        }
        self.append("evidence.jsonl", record)
        self.append("traffic.jsonl", traffic_record)
        self._traffic_by_evidence[evidence_id] = traffic_id
        self._traffic_by_id[traffic_id] = traffic_record
        return evidence_id

    def capture_transport_error(self, request_record, error_type, elapsed_ms, reason):
        """Persist a failed outbound attempt with a unique traffic/evidence reference."""
        self.seq += 1
        safe_request = redact_payload(request_record if isinstance(request_record, dict) else {})
        if isinstance(safe_request, dict) and "url" in safe_request:
            safe_request["url"] = redact_url(safe_request["url"])
        material = json.dumps({"sequence": self.seq, "request": safe_request,
                               "error_type": str(error_type)[:100]}, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        digest = sha256(material)
        evidence_id = f"ev-{self.seq:05d}-{digest[:10]}"
        traffic_id = f"tr-{self.seq:05d}-{digest[10:22]}"
        timestamp = time.time()
        request_body = request_record.get("body") if isinstance(request_record, dict) else None
        if request_body is None and isinstance(request_record, dict):
            request_body = request_record.get("json")
        if isinstance(request_body, bytes): body_bytes = request_body
        elif isinstance(request_body, str): body_bytes = request_body.encode("utf-8", errors="replace")
        elif request_body is None: body_bytes = b""
        else: body_bytes = json.dumps(request_body, sort_keys=True, separators=(",", ":"), default=str).encode()
        method = str(request_record.get("method", "GET")).upper() if isinstance(request_record, dict) else "GET"
        url = redact_url(request_record.get("url", "")) if isinstance(request_record, dict) else ""
        headers = request_record.get("headers", {}) if isinstance(request_record, dict) else {}
        traffic_record = {"traffic_id": traffic_id, "sequence": self.seq, "timestamp": timestamp,
                          "evidence_id": evidence_id,
                          "request": {"method": method, "url": url,
                                      "headers": redact_headers(headers if isinstance(headers, dict) else {}),
                                      "body_sha256": sha256(body_bytes), "body_bytes": len(body_bytes)},
                          "response": {"status": None, "transport_error": str(error_type)[:100],
                                       "elapsed_ms": elapsed_ms}}
        evidence_record = {"evidence_id": evidence_id, "traffic_id": traffic_id, "timestamp": timestamp,
                           "reason": redact_text(reason)[:200], "request": safe_request,
                           "transport_error": str(error_type)[:100], "elapsed_ms": elapsed_ms}
        self.append("evidence.jsonl", evidence_record)
        self.append("traffic.jsonl", traffic_record)
        self._traffic_by_evidence[evidence_id] = traffic_id
        self._traffic_by_id[traffic_id] = traffic_record
        return evidence_id

    def traffic_id_for(self, evidence_id):
        return self._traffic_by_evidence.get(evidence_id)

    def verify_traffic(self):
        """Verify unique traffic IDs resolve to matching persisted evidence records."""
        evidence = {}
        errors = []
        evidence_path = self.run_dir / "evidence.jsonl"
        traffic_path = self.run_dir / "traffic.jsonl"
        if not evidence_path.exists() or not traffic_path.exists():
            return {"valid": False, "traffic_records": 0, "errors": ["traffic_or_evidence_file_missing"]}
        for line_no, line in enumerate(evidence_path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                row = json.loads(line)
                if row.get("evidence_id"):
                    evidence[row["evidence_id"]] = row
            except json.JSONDecodeError:
                errors.append(f"malformed_evidence:{line_no}")
        seen = set()
        count = 0
        for line_no, line in enumerate(traffic_path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                row = json.loads(line)
                traffic_id, evidence_id = row.get("traffic_id"), row.get("evidence_id")
                if not traffic_id or traffic_id in seen:
                    errors.append(f"missing_or_duplicate_traffic_id:{line_no}")
                    continue
                seen.add(traffic_id); count += 1
                linked = evidence.get(evidence_id)
                if not linked or linked.get("traffic_id") != traffic_id:
                    errors.append(f"unresolved_traffic_evidence:{line_no}")
                elif row.get("response", {}).get("body_sha256") is not None and row.get("response", {}).get("body_sha256") != linked.get("response", {}).get("body_sha256"):
                    errors.append(f"traffic_response_hash_mismatch:{line_no}")
                elif row.get("response", {}).get("transport_error") != linked.get("transport_error") and row.get("response", {}).get("transport_error") is not None:
                    errors.append(f"traffic_transport_error_mismatch:{line_no}")
            except (json.JSONDecodeError, AttributeError, TypeError):
                errors.append(f"malformed_traffic:{line_no}")
        for evidence_id, row in evidence.items():
            traffic_id = row.get("traffic_id")
            if traffic_id and traffic_id not in seen:
                errors.append("missing_traffic_index:" + evidence_id)
        # Validate the finding -> traffic -> evidence edge as well. A valid
        # traffic ID must not be enough to attach unrelated evidence to a finding.
        findings_path = self.run_dir / "findings.jsonl"
        if findings_path.exists():
            for line_no, line in enumerate(findings_path.read_text(encoding="utf-8").splitlines(), 1):
                try:
                    finding = json.loads(line)
                    if not isinstance(finding, dict):
                        errors.append(f"malformed_finding:{line_no}")
                        continue
                    traffic_ids = finding.get("traffic_ids", [])
                    if not isinstance(traffic_ids, list) or any(not isinstance(tid, str) for tid in traffic_ids):
                        errors.append(f"invalid_finding_traffic_ids:{line_no}")
                        continue
                    evidence_refs = set()
                    if isinstance(finding.get("evidence_id"), str): evidence_refs.add(finding["evidence_id"])
                    if isinstance(finding.get("evidence_ids"), list):
                        evidence_refs.update(x for x in finding["evidence_ids"] if isinstance(x, str))
                    for traffic_id in traffic_ids:
                        traffic_row = self._traffic_by_id.get(traffic_id)
                        if traffic_row is None:
                            errors.append(f"unknown_finding_traffic_id:{line_no}")
                        elif traffic_row.get("evidence_id") not in evidence_refs:
                            errors.append(f"finding_traffic_evidence_mismatch:{line_no}")
                except (json.JSONDecodeError, AttributeError, TypeError):
                    errors.append(f"malformed_finding:{line_no}")
        return {"valid": not errors, "traffic_records": count, "errors": errors}
    def finding(self, finding):
        import hashlib
        if not isinstance(finding, dict):
            raise ValueError("finding must be an object")
        explicit_traffic_ids = finding.get("traffic_ids")
        if explicit_traffic_ids is not None:
            if not isinstance(explicit_traffic_ids, list) or any(not isinstance(item, str) or item not in self._traffic_by_id for item in explicit_traffic_ids):
                raise ValueError("finding traffic_ids must reference existing persisted traffic records")
        evidence_ids = []
        if finding.get("evidence_id"):
            evidence_ids.append(finding["evidence_id"])
        if isinstance(finding.get("evidence_ids"), list):
            evidence_ids.extend(item for item in finding["evidence_ids"] if isinstance(item, str))
        linked_traffic = [self._traffic_by_evidence[item] for item in evidence_ids if item in self._traffic_by_evidence]
        if explicit_traffic_ids is not None:
            if explicit_traffic_ids and not evidence_ids:
                raise ValueError("explicit finding traffic_ids require linked persisted evidence IDs")
            for traffic_id in explicit_traffic_ids:
                traffic_evidence_id = self._traffic_by_id[traffic_id].get("evidence_id")
                if traffic_evidence_id not in evidence_ids:
                    raise ValueError("finding traffic_ids must point to the finding's own evidence")
            linked_traffic.extend(explicit_traffic_ids)
        if linked_traffic:
            finding["traffic_ids"] = list(dict.fromkeys(linked_traffic))
        canonical = json.dumps({"check":finding.get("check"),"title":finding.get("title"),
                                "url":finding.get("url"),"details":finding.get("details",{})},
                               sort_keys=True,default=str)
        key=hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        if key in self._finding_keys:
            self.event({"type":"finding_deduplicated","dedupe_key":key,"title":finding.get("title")})
            return None
        self._finding_keys.add(key)
        self._finding_count += 1
        finding["finding_id"] = f"fn-{self._finding_count:05d}"
        finding["dedupe_key"] = key
        self.append("findings.jsonl", finding)
        return finding["finding_id"]
    def event(self, event):
        self.append("events.jsonl", event)
