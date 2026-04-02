import csv, re, threading, time, logging
from datetime import datetime
from pathlib import Path
from vulnlab.scanner.openvas_scanner import GVMClient, ScanStatus
from vulnlab.core.container import ContainerManager

FIELDS = ["image","image_slug","container_id","container_ip","scan_date","scan_timestamp","gvm_task_id","gvm_target_id","gvm_report_id","vuln_critical","vuln_high","vuln_medium","vuln_low","vuln_log","vuln_total","reports_saved","reports_dir","worker_id"]
_GVM_SEM = threading.Semaphore(12)

class ScanWorker:
    def __init__(self, wid, gvm_cfg, c_cfg, db, out_dir, fmts, shutdown, logger):
        self.wid, self.db, self.out_dir, self.fmts, self.shutdown, self.logger = wid, db, Path(out_dir), fmts, shutdown, logger
        self.gvm, self.cm = GVMClient(gvm_cfg, logger), ContainerManager(c_cfg, logger)

    def run(self, job):
        img = job["image"]
        res = {"image": img, "status": "failed", "error": ""}
        stop_hb = threading.Event()
        threading.Thread(target=self._hb, args=(img, stop_hb), daemon=True).start()
        try:
            with self.cm.lifecycle(img) as (ip, cid, skip):
                if not ip:
                    res.update(status="skipped" if skip else "failed", error=skip or "no_ip")
                    return res
                res.update(container_ip=ip, container_id=cid)
                if self.shutdown.is_set(): return {"image": img, "status": "failed", "error": "shutdown"}
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                _GVM_SEM.acquire()
                try:
                    tid = self._retry(lambda: self.gvm.create_target(f"ms-{job['id']}-{ts}", ip), img, "target")
                    tkid = self._retry(lambda: self.gvm.create_task(f"ms-{job['id']}-{ts}", tid), img, "task")
                    self.gvm.start_task(tkid)
                    stat, rid = self.gvm.wait_for_task(tkid, ip, self.shutdown.is_set)
                finally: _GVM_SEM.release()
                if stat != ScanStatus.DONE: return {**res, "error": str(stat), "task_id": tkid}
                v = self.gvm.get_report_summary(rid)
                p = self._save(img, rid, cid, ip, tkid, tid, v, ts)
                vulns = {f"vuln_{k}": v.get(k, 0) for k in ["critical", "high", "medium", "low", "log", "total"]}
                if self.gvm.config.cleanup_after_scan: self.gvm.delete_task(tkid); self.gvm.delete_target(tid)
                res.update(status="done", task_id=tkid, target_id=tid, report_id=rid, reports_path=str(p), **vulns)
        except Exception as e: res["error"] = str(e); raise
        finally: stop_hb.set()
        return res

    def _retry(self, fn, img, step):
        for i in range(3):
            try: return fn()
            except Exception as e:
                if i == 2: raise
                time.sleep(10)

    def _hb(self, img, stop):
        while not stop.wait(60):
            try: self.db.heartbeat(img)
            except: pass

    def _save(self, img, rid, cid, ip, tkid, tid, v, ts):
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "__", img).strip("_")
        out = self.out_dir / slug / f"scan_{slug}_{ts}"
        out.mkdir(parents=True, exist_ok=True)
        saved = []
        for f in self.fmts:
            c = self.gvm.get_report(rid, f)
            if c: (out / f"scan_{slug}_{ts}.{f.lower()}").write_bytes(c); saved.append(f)
        vulns = {f"vuln_{k}": v.get(k, 0) for k in ["critical", "high", "medium", "low", "log", "total"]}
        row = {"image":img, "image_slug":slug, "container_id":cid[:12] if cid else "", "container_ip":ip, "scan_date":datetime.now().strftime("%Y-%m-%d"), "scan_timestamp":ts, "gvm_task_id":tkid, "gvm_target_id":tid, "gvm_report_id":rid, "reports_saved":"|".join(saved), "reports_dir":str(out.resolve()), "worker_id":self.wid, **vulns}
        with open(out / "scan_info.csv", "w", newline="") as f:
            w = csv.DictWriter(f, FIELDS); w.writeheader(); w.writerow(row)
        g_csv = self.out_dir / "all_scans_summary.csv"
        ext = g_csv.exists()
        with open(g_csv, "a", newline="") as f:
            w = csv.DictWriter(f, FIELDS); 
            if not ext: w.writeheader()
            w.writerow(row)
        return out
