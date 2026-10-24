import os
import pathlib
import tempfile
import time
import unittest

from appsec_agent.evidence import EvidenceStore
from appsec_agent.operations import EvidenceRetentionManager, backup_runtime_db, restore_runtime_db, runtime_health
from appsec_agent.runtime_store import RuntimeStore, policy_digest


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def test_runtime_health_reports_integrity_and_counts(self):
        db = self.root / "runtime.sqlite3"
        store = RuntimeStore(db)
        job = store.create_job(policy_digest="sha256:test")
        store.add_task(job["id"], "one", "fixture")
        report = runtime_health(db)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["integrity"], "ok")
        self.assertEqual(report["jobs"]["running"], 1)
        self.assertEqual(report["tasks"]["pending"], 1)
        self.assertEqual(report["expired_leases"], 0)
        self.assertEqual(report["failed_tasks"], 0)
        self.assertEqual(report["recovery_events"], 0)
        self.assertEqual(runtime_health(self.root / "missing.sqlite3")["error"], "database_missing")

    def test_backup_and_restore_round_trip(self):
        source = self.root / "source.sqlite3"
        store = RuntimeStore(source)
        job = store.create_job(policy_digest="sha256:test")
        store.add_task(job["id"], "one", "fixture")
        backup = self.root / "backups" / "runtime.sqlite3"
        info = backup_runtime_db(source, backup)
        self.assertEqual(info["integrity"], "ok")
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        restored = self.root / "restore.sqlite3"
        restored_info = restore_runtime_db(backup, restored)
        self.assertEqual(restored_info["integrity"], "ok")
        self.assertEqual(RuntimeStore(restored).get_job(job["id"])["id"], job["id"])
        with self.assertRaises(ValueError): backup_runtime_db(source, backup)

    def test_restore_rejects_non_runtime_sqlite(self):
        path = self.root / "not-artemis.sqlite3"
        import sqlite3
        with sqlite3.connect(path) as conn: conn.execute("CREATE TABLE random(value TEXT)")
        with self.assertRaises(ValueError): restore_runtime_db(path, self.root / "bad-restore.sqlite3")

    def test_retention_dry_run_never_deletes_and_apply_archives_first(self):
        runs = self.root / "runs"; archive = self.root / "archive"
        old = runs / "old-run"; old.mkdir(parents=True)
        store = EvidenceStore(old)
        store.capture({"method": "GET", "url": "https://staging.example.test/"}, 200, {}, b"ok", 1, "fixture")
        old_time = time.time() - 20 * 86400
        os.utime(old, (old_time, old_time))
        manager = EvidenceRetentionManager(runs, archive)
        dry = manager.prune_expired_runs(retention_days=10, now=time.time(), apply=False)
        self.assertEqual(dry["candidates"], ["old-run"])
        self.assertTrue(old.exists())
        applied = manager.prune_expired_runs(retention_days=10, now=time.time(), apply=True)
        self.assertEqual(applied["deleted"], ["old-run"])
        self.assertFalse(old.exists())
        self.assertTrue(pathlib.Path(applied["archived"][0]["archive"]).is_file())

    def test_retention_refuses_invalid_days(self):
        with self.assertRaises(ValueError):
            EvidenceRetentionManager(self.root, self.root / "archive").prune_expired_runs(retention_days=0)


if __name__ == "__main__": unittest.main()
