import csv
import logging
import re
import threading
import time
from datetime import datetime
from pathlib import Path

from vulnlab.scanner.openvas_scanner import Config, GVMClient, ScanStatus
from vulnlab.core.container import ContainerConfig, ContainerManager
from vulnlab.core.db import ScanDB

CSV_FIELDS = [
    "image", "image_slug", "container_id", "container_ip",
    "scan_date", "scan_timestamp",
    "gvm_task_id", "gvm_target_id", "gvm_report_id",
    "vuln_high", "vuln_medium", "vuln_low", "vuln_log", "vuln_total",
    "reports_saved", "reports_dir", "worker_id",
]

# Global semaphore: limits concurrent active GVM scan tasks.
# Containers can still be pulled/started in parallel (controlled by --workers),
# but only GVM_MAX_CONCURRENT tasks will be submitted to openvasd at once.
# openvasd becomes unstable with too many concurrent tasks (ospd socket loss).
GVM_MAX_CONCURRENT = 12
_gvm_sem = threading.Semaphore(GVM_MAX_CONCURRENT)


class ScanWorker:
    def __init__(self, worker_id: str, gvm_cfg: Config, container_cfg: ContainerConfig, db: ScanDB, output_dir: str, report_formats: list, shutdown: threading.Event, logger: logging.Logger):
        self.worker_id = worker_id
        self.db = db
        self.output_dir = Path(output_dir)
        self.report_formats = report_formats
        self.shutdown = shutdown
        self.logger = logger
        # GVMClient — no signal handlers, safe to use in threads
        self.gvm = GVMClient(gvm_cfg, logger)
        self.cm = ContainerManager(container_cfg, logger)

    def run(self, job: dict) -> dict:
        image = job["image"]
        result = {"image": image, "status": "failed", "error": ""}

        stop_hb = threading.Event()
        threading.Thread(target=self._heartbeat_loop, args=(image, stop_hb), daemon=True).start()

        try:
            with self.cm.lifecycle(image) as (container_ip, container_id):
                if not container_ip:
                    result["error"] = "container lifecycle failed (no IP)"
                    return result

                result["container_ip"] = container_ip
                result["container_id"] = container_id

                if self.shutdown.is_set():
                    result["error"] = "shutdown"
                    return result

                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                label = f"{image}@{container_ip}"

                # Acquire global GVM slot — limits concurrent openvasd tasks to
                # GVM_MAX_CONCURRENT regardless of how many container workers exist.
                # Container is already running while we wait for the slot.
                self.logger.debug(f"[{self.worker_id}] Waiting for GVM slot ({label})")
                _gvm_sem.acquire()
                task_id = target_id = None
                try:
                    target_id = self._retry(lambda: self.gvm.create_target(f"ms-{job['id']}-{ts}", container_ip), label, "create_target")
                    task_id   = self._retry(lambda: self.gvm.create_task(f"ms-{job['id']}-{ts}", target_id), label, "create_task")
                    self._retry(lambda: self.gvm.start_task(task_id), label, "start_task")

                    status, report_id = self.gvm.wait_for_task(task_id, container_ip, should_stop=self.shutdown.is_set)
                finally:
                    _gvm_sem.release()

                if status != ScanStatus.DONE:
                    result["error"] = str(status)
                    result["task_id"] = task_id
                    result["target_id"] = target_id
                    return result

                vulns = self.gvm.get_report_summary(report_id or "")
                reports_dir = self._save_reports(image, report_id or "", container_id or "", container_ip, task_id, target_id, vulns, ts)

                if self.gvm.config.cleanup_after_scan:
                    self.gvm.delete_task(task_id)
                    self.gvm.delete_target(target_id)

                result.update({
                    "status":       "done",
                    "task_id":      task_id,
                    "target_id":    target_id,
                    "report_id":    report_id,
                    "reports_path": str(reports_dir),
                    "vuln_high":    vulns.get("high",   0),
                    "vuln_medium":  vulns.get("medium", 0),
                    "vuln_low":     vulns.get("low",    0),
                    "vuln_log":     vulns.get("log",    0),
                    "vuln_total":   vulns.get("total",  0),
                })
        except Exception as e:
            result["error"] = str(e)
            if "GVM not reachable" in str(e):
                raise
        finally:
            stop_hb.set()

        return result

    def _retry(self, fn, label: str, step: str, attempts: int = 3):
        last: Exception = RuntimeError("no attempts")
        for i in range(1, attempts + 1):
            try:
                return fn()
            except Exception as e:
                last = e
                if i < attempts:
                    self.logger.warning(f"[{self.worker_id}] {step} failed for {label} (attempt {i}): {e}")
                    time.sleep(10)
        raise last

    def _heartbeat_loop(self, image: str, stop: threading.Event):
        while not stop.wait(60):
            try:
                self.db.heartbeat(image)
            except Exception:
                pass

    def _save_reports(self, image: str, report_id: str, container_id: str,
                      ip: str, task_id: str, target_id: str, vulns: dict, ts: str) -> Path:
        image_slug = re.sub(r"[^a-zA-Z0-9._-]+", "__", image).strip("_")
        scan_name  = f"scan_{image_slug}_{ts}"
        out = self.output_dir / image_slug / scan_name
        out.mkdir(parents=True, exist_ok=True)

        saved_formats = []
        for fmt in self.report_formats:
            content = self.gvm.get_report(report_id, fmt)
            if content:
                try:
                    (out / f"{scan_name}.{fmt.lower()}").write_bytes(content)
                    saved_formats.append(fmt)
                except OSError as e:
                    self.logger.warning(f"Could not save {fmt} for {image}: {e}")

        row = {
            "image":          image,
            "image_slug":     image_slug,
            "container_id":   container_id[:12] if container_id else "",
            "container_ip":   ip,
            "scan_date":      datetime.now().strftime("%Y-%m-%d"),
            "scan_timestamp": ts,
            "gvm_task_id":    task_id,
            "gvm_target_id":  target_id,
            "gvm_report_id":  report_id,
            "vuln_high":      vulns.get("high",   0),
            "vuln_medium":    vulns.get("medium", 0),
            "vuln_low":       vulns.get("low",    0),
            "vuln_log":       vulns.get("log",    0),
            "vuln_total":     vulns.get("total",  0),
            "reports_saved":  "|".join(saved_formats),
            "reports_dir":    str(out.resolve()),
            "worker_id":      self.worker_id,
        }

        try:
            with open(out / "scan_info.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                w.writeheader()
                w.writerow(row)
        except OSError:
            pass

        global_csv = self.output_dir / "all_scans_summary.csv"
        write_header = not global_csv.exists()
        try:
            with open(global_csv, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                if write_header:
                    w.writeheader()
                w.writerow(row)
        except OSError:
            pass

        return out
