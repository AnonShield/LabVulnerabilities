import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional
from vulnlab.discovery.catalog import ImageSpec

_SCHEMA = [
    "CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, image TEXT NOT NULL UNIQUE, name TEXT, status TEXT NOT NULL DEFAULT 'pending', worker_id TEXT, container_id TEXT, container_ip TEXT, task_id TEXT, target_id TEXT, report_id TEXT, reports_path TEXT, attempt INTEGER NOT NULL DEFAULT 0, started_at TEXT, finished_at TEXT, heartbeat_at TEXT, error TEXT, vuln_high INTEGER NOT NULL DEFAULT 0, vuln_medium INTEGER NOT NULL DEFAULT 0, vuln_low INTEGER NOT NULL DEFAULT 0, vuln_log INTEGER NOT NULL DEFAULT 0, vuln_total INTEGER NOT NULL DEFAULT 0, pull_count INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now')))",
    "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_worker ON jobs(worker_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_pull_count ON jobs(pull_count DESC, status)"
]

def _now(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

class ScanDB:
    def __init__(self, path: str = "mass_scan.db", stale: int = 5):
        self._path, self._stale, self._lock = path, stale, threading.Lock()
        with self._conn() as c:
            for s in _SCHEMA: c.execute(s)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL"); conn.execute("PRAGMA synchronous=NORMAL")
            try: yield conn; conn.commit()
            except: conn.rollback(); raise
            finally: conn.close()

    def seed(self, imgs: Iterable[ImageSpec]):
        with self._conn() as c:
            for i in imgs: c.execute("INSERT OR IGNORE INTO jobs (image, name, pull_count) VALUES (?, ?, ?)", (i.image, i.name, i.pull_count))

    def claim(self, wid: str, max_try: int = 3) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM jobs WHERE status='pending' AND attempt < ? ORDER BY pull_count DESC, id LIMIT 1", (max_try,)).fetchone()
            if not row: return None
            t = _now()
            c.execute("UPDATE jobs SET status='running', worker_id=?, started_at=?, heartbeat_at=?, attempt=attempt+1 WHERE id=?", (wid, t, t, row["id"]))
            res = dict(row); res.update(status="running", worker_id=wid, attempt=res["attempt"]+1)
            return res

    def heartbeat(self, img: str):
        with self._conn() as c: c.execute("UPDATE jobs SET heartbeat_at=? WHERE image=?", (_now(), img))

    def done(self, img: str, res: dict):
        with self._conn() as c:
            c.execute("UPDATE jobs SET status='done', finished_at=?, container_id=?, container_ip=?, task_id=?, target_id=?, report_id=?, reports_path=?, error=NULL, vuln_high=?, vuln_medium=?, vuln_low=?, vuln_log=?, vuln_total=? WHERE image=?",
                (_now(), res.get("container_id"), res.get("container_ip"), res.get("task_id"), res.get("target_id"), res.get("report_id"), res.get("reports_path"), int(res.get("vuln_high") or 0), int(res.get("vuln_medium") or 0), int(res.get("vuln_low") or 0), int(res.get("vuln_log") or 0), int(res.get("vuln_total") or 0), img))

    def skip(self, img: str, err: str):
        with self._conn() as c: c.execute("UPDATE jobs SET status='skipped', finished_at=?, error=? WHERE image=?", (_now(), (err or "")[:2000], img))

    def fail(self, img: str, err: str):
        with self._conn() as c: c.execute("UPDATE jobs SET status='failed', finished_at=?, error=? WHERE image=?", (_now(), (err or "")[:2000], img))

    def reset_stale(self, mins: Optional[int] = None) -> int:
        lim = (datetime.now(timezone.utc) - timedelta(minutes=mins or self._stale)).strftime("%Y-%m-%dT%H:%M:%S")
        with self._conn() as c:
            return c.execute("UPDATE jobs SET status='pending', worker_id=NULL, error='stale' WHERE status='running' AND (heartbeat_at < ?) AND attempt < 3", (lim,)).rowcount

    def stats(self) -> dict:
        with self._conn() as c:
            counts = {str(r[0]): r[1] for r in c.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status").fetchall()}
        return {k: counts.get(k, 0) for k in ["pending", "running", "done", "failed", "skipped"]} | {"total": sum(counts.values())}
