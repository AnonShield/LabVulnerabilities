"""
SQLite-backed job queue for single-machine multi-thread scanning.

For 20-machine distributed use: pre-split images.txt into 20 parts and run
one instance per machine — each with its own db file.  No shared DB needed.
"""
import csv
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional

from vulnlab.discovery.catalog import ImageSpec

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS jobs (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        image        TEXT    NOT NULL UNIQUE,
        name         TEXT,
        status       TEXT    NOT NULL DEFAULT 'pending',
        worker_id    TEXT,
        container_id TEXT,
        container_ip TEXT,
        task_id      TEXT,
        target_id    TEXT,
        report_id    TEXT,
        reports_path TEXT,
        attempt      INTEGER NOT NULL DEFAULT 0,
        started_at   TEXT,
        finished_at  TEXT,
        heartbeat_at TEXT,
        error        TEXT,
        vuln_high    INTEGER NOT NULL DEFAULT 0,
        vuln_medium  INTEGER NOT NULL DEFAULT 0,
        vuln_low     INTEGER NOT NULL DEFAULT 0,
        vuln_total   INTEGER NOT NULL DEFAULT 0,
        created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
    )""",
    "CREATE INDEX IF NOT EXISTS idx_jobs_status  ON jobs(status)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_worker  ON jobs(worker_id, status)",
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class ScanDB:
    """
    Thread-safe SQLite job queue.

    Concurrency model:
      - WAL mode: N threads read simultaneously.
      - BEGIN IMMEDIATE + _write_lock: claim_job is serialised so two threads
        can never claim the same row.
      - heartbeat thread updates its row independently (simple UPDATE, safe).
    """

    def __init__(self, path: str = "mass_scan.db", stale_minutes: int = 5):
        self._path = path
        self._stale = stale_minutes
        self._wlock = threading.Lock()
        self._setup()

    # ------------------------------------------------------------------
    # Connections
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _setup(self):
        with self._conn() as c:
            for stmt in _SCHEMA:
                c.execute(stmt)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seed(self, images: Iterable[ImageSpec], skip_existing: bool = True):
        """Populate queue from any ImageSource. Idempotent by default."""
        kw = "OR IGNORE" if skip_existing else "OR REPLACE"
        with self._wlock, self._conn() as c:
            for img in images:
                c.execute(
                    f"INSERT {kw} INTO jobs (image, name) VALUES (?, ?)",
                    (img.image, img.name),
                )

    def claim_job(self, worker_id: str, max_attempts: int = 3) -> Optional[dict]:
        """
        Atomically claim the next pending job.
        BEGIN IMMEDIATE + _wlock ensures no two threads grab the same row.
        Returns row dict or None if queue is empty.
        """
        now = _now()
        with self._wlock:
            conn = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    """SELECT * FROM jobs
                       WHERE status='pending' AND attempt < ?
                       ORDER BY id LIMIT 1""",
                    (max_attempts,),
                ).fetchone()
                if row is None:
                    conn.commit()
                    return None
                conn.execute(
                    """UPDATE jobs
                       SET status='running', worker_id=?,
                           started_at=?, heartbeat_at=?, attempt=attempt+1
                       WHERE id=?""",
                    (worker_id, now, now, row["id"]),
                )
                conn.commit()
                result = dict(row)
                result["status"]  = "running"
                result["worker_id"] = worker_id
                result["attempt"] = int(result.get("attempt") or 0) + 1
                return result
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def heartbeat(self, image: str):
        """Worker calls this every 60 s to signal it is still alive."""
        with self._conn() as c:
            c.execute(
                "UPDATE jobs SET heartbeat_at=? WHERE image=?", (_now(), image)
            )

    def complete(self, image: str, result: dict):
        with self._conn() as c:
            c.execute(
                """UPDATE jobs SET
                       status='done', finished_at=?,
                       container_id=?, container_ip=?,
                       task_id=?, target_id=?, report_id=?, reports_path=?,
                       error=NULL,
                       vuln_high=?, vuln_medium=?, vuln_low=?, vuln_total=?
                   WHERE image=?""",
                (
                    _now(),
                    result.get("container_id"),
                    result.get("container_ip"),
                    result.get("task_id"),
                    result.get("target_id"),
                    result.get("report_id"),
                    result.get("reports_path"),
                    int(result.get("vuln_high") or 0),
                    int(result.get("vuln_medium") or 0),
                    int(result.get("vuln_low") or 0),
                    int(result.get("vuln_total") or 0),
                    image,
                ),
            )

    def fail(self, image: str, error: str):
        with self._conn() as c:
            c.execute(
                "UPDATE jobs SET status='failed', finished_at=?, error=? WHERE image=?",
                (_now(), (error or "")[:2000], image),
            )

    def reset_stale(self, timeout_minutes: Optional[int] = None) -> int:
        """
        Reclaim 'running' jobs whose heartbeat expired.
        Called on every startup to recover from crashes or Ctrl-C.
        """
        minutes = timeout_minutes or self._stale
        threshold = (
            datetime.now(timezone.utc) - timedelta(minutes=minutes)
        ).strftime("%Y-%m-%dT%H:%M:%S")
        with self._conn() as c:
            cur = c.execute(
                """UPDATE jobs
                   SET status='pending', worker_id=NULL,
                       error='reclaimed: stale heartbeat'
                   WHERE status='running'
                   AND   (heartbeat_at IS NULL OR heartbeat_at < ?)
                   AND   attempt < 3""",
                (threshold,),
            )
            return cur.rowcount

    def stats(self) -> dict:
        with self._conn() as c:
            rows = c.execute(
                "SELECT status, COUNT(*) FROM jobs GROUP BY status"
            ).fetchall()
        counts = {str(r[0]): int(r[1]) for r in rows}
        return {
            "pending": counts.get("pending", 0),
            "running": counts.get("running", 0),
            "done":    counts.get("done",    0),
            "failed":  counts.get("failed",  0),
            "total":   sum(counts.values()),
        }

    def export_csv(self, path: str):
        with self._conn() as c:
            cursor = c.execute("SELECT * FROM jobs ORDER BY id")
            cols = [d[0] for d in cursor.description]
            rows = cursor.fetchall()
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            w.writerows(rows)
