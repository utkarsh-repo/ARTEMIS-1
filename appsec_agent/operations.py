"""Local health, SQLite backup/restore and evidence retention helpers."""
from __future__ import annotations
import os
import pathlib
import shutil
import sqlite3
import time
import uuid
from .evidence import EvidenceStore, sha256
from .runtime_store import RuntimeStore, SCHEMA_VERSION


def runtime_health(db_path) -> dict:
    path = pathlib.Path(db_path)
    report = {"ok": False, "database_exists": path.is_file(), "database_readable": False,
              "integrity": "unknown", "jobs": {}, "tasks": {}, "checked_at": time.time()}
    if not path.is_file():
        report["error"] = "database_missing"
        return report
    try:
        with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=2) as conn:
            report["database_readable"] = True
            report["integrity"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if report["integrity"] != "ok":
                report["error"] = "sqlite_integrity_failed"
                return report
            for status, count in conn.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status"):
                report["jobs"][status] = count
            for status, count in conn.execute("SELECT status, COUNT(*) FROM tasks GROUP BY status"):
                report["tasks"][status] = count
            report["expired_leases"] = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status IN ('leased','running') AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
                (time.time(),)).fetchone()[0]
            report["failed_tasks"] = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='failed'").fetchone()[0]
            report["recovery_events"] = conn.execute(
                "SELECT COUNT(*) FROM runtime_events WHERE event_type LIKE '%lease_expired%' OR event_type LIKE '%recovery%'"
            ).fetchone()[0]
            report["schema_version"] = conn.execute("SELECT value FROM runtime_meta WHERE key='schema_version'").fetchone()[0]
        report["ok"] = True
    except (sqlite3.Error, OSError, TypeError) as exc:
        report["error"] = type(exc).__name__
    return report


def backup_runtime_db(source, destination) -> dict:
    src, dst = pathlib.Path(source), pathlib.Path(destination)
    if not src.is_file() or src.is_symlink(): raise ValueError("source runtime database must be a regular file")
    if dst.exists() or dst.is_symlink(): raise ValueError("backup destination must not already exist")
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    src_conn = sqlite3.connect(f"file:{src.resolve()}?mode=ro", uri=True)
    dst_conn = sqlite3.connect(str(dst))
    try:
        src_conn.backup(dst_conn)
        integrity = dst_conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok": raise ValueError("backup integrity check failed")
    finally:
        dst_conn.close(); src_conn.close()
    os.chmod(dst, 0o600)
    return {"path": str(dst), "sha256": sha256(dst.read_bytes()), "integrity": "ok", "bytes": dst.stat().st_size}


def restore_runtime_db(backup, destination) -> dict:
    src, dst = pathlib.Path(backup), pathlib.Path(destination)
    if not src.is_file() or src.is_symlink(): raise ValueError("backup must be a regular file")
    if dst.exists() or dst.is_symlink(): raise ValueError("restore destination must not already exist")
    with sqlite3.connect(f"file:{src.resolve()}?mode=ro", uri=True) as conn:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok": raise ValueError("backup integrity check failed")
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"runtime_meta", "jobs", "tasks"}.issubset(tables): raise ValueError("backup is not an ARTEMIS runtime database")
        row = conn.execute("SELECT value FROM runtime_meta WHERE key='schema_version'").fetchone()
        if not row or int(row[0]) > int(SCHEMA_VERSION): raise ValueError("backup schema is missing or newer than this runtime")
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    src_conn = sqlite3.connect(f"file:{src.resolve()}?mode=ro", uri=True); dst_conn = sqlite3.connect(str(dst))
    try: src_conn.backup(dst_conn)
    finally: dst_conn.close(); src_conn.close()
    os.chmod(dst, 0o600)
    # Opening the restored DB runs supported additive migrations and confirms it is usable.
    RuntimeStore(dst)
    return {"path": str(dst), "sha256": sha256(dst.read_bytes()), "integrity": "ok", "bytes": dst.stat().st_size}


class EvidenceRetentionManager:
    """Explicit, archive-before-delete retention for complete assessment directories."""
    def __init__(self, root, archive_dir):
        self.root = pathlib.Path(root); self.archive_dir = pathlib.Path(archive_dir)

    def prune_expired_runs(self, *, retention_days: int, now: float | None = None, apply: bool = False) -> dict:
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be an integer from 1 to 3650")
        now = time.time() if now is None else float(now)
        cutoff = now - retention_days * 86400
        result = {"dry_run": not apply, "candidates": [], "archived": [], "deleted": [], "errors": []}
        if not self.root.is_dir(): return result
        for run_dir in sorted(p for p in self.root.iterdir() if p.is_dir() and not p.is_symlink()):
            if run_dir.stat().st_mtime >= cutoff: continue
            if not (run_dir / "evidence.jsonl").exists() and not (run_dir / "findings.jsonl").exists(): continue
            result["candidates"].append(run_dir.name)
            if not apply: continue
            try:
                store = EvidenceStore(run_dir)
                if not store.verify_manifest()["valid"]: raise ValueError("integrity verification failed")
                self.archive_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                archive_path = self.archive_dir / (run_dir.name + "-" + uuid.uuid4().hex[:8] + ".zip")
                manifest = store.export_bundle(archive_path)
                result["archived"].append({"run": run_dir.name, "archive": str(archive_path), "sha256": sha256(archive_path.read_bytes())})
                if not manifest["integrity"]["valid"]: raise ValueError("export integrity failed")
                shutil.rmtree(run_dir)
                result["deleted"].append(run_dir.name)
            except Exception as exc:
                result["errors"].append({"run": run_dir.name, "error": type(exc).__name__})
        return result
