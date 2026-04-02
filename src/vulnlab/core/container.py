import logging
import socket
import threading
import time
import uuid
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple
import docker
import docker.errors
import docker.types
import requests as _requests

PROBE_PORTS: Tuple[int, ...] = (80, 443, 8080, 8443, 8888, 8000, 3000, 5000, 22, 21, 23, 3306, 5432, 27017, 6379, 9200, 5601, 8161, 15672, 5672, 9092, 2181, 9090, 3100, 9093, 9094)
_TMPFS = {"/tmp": "rw,noexec,nosuid,size=64m", "/run": "rw,noexec,nosuid,size=32m", "/var/run": "rw,noexec,nosuid,size=32m"}

@dataclass
class ContainerConfig:
    network: str = "trabalho_vulnnet"
    network_subnet: str = "172.30.0.0/16"
    startup_wait: int = 15
    health_timeout: int = 90
    scan_watchdog: int = 3600
    stop_timeout: int = 10
    pull_retries: int = 3
    pull_retry_delay: int = 60
    max_image_size_mb: int = 10240
    dockerhub_username: str = ""
    dockerhub_password: str = ""
    mem_limit: str = "512m"
    cpu_quota: int = 100000
    pids_limit: int = 256
    ulimit_nofile: int = 1024
    read_only_rootfs: bool = True
    drop_all_caps: bool = True
    no_new_privileges: bool = True
    remove_image_after: bool = True
    prune_every: int = 20

_API_SEM = threading.Semaphore(5)

class ContainerManager:
    def __init__(self, cfg: ContainerConfig, logger: logging.Logger):
        self.cfg, self.logger = cfg, logger
        self._scan_count = 0
        self._lock = threading.Lock()
        try:
            self.client = docker.from_env(timeout=300)
            self.client.ping()
        except Exception as e: raise RuntimeError(f"Docker error: {e}")
        self._ensure_net()
        if cfg.dockerhub_username and cfg.dockerhub_password: self._login()

    def _ensure_net(self):
        try:
            net = self.client.networks.get(self.cfg.network)
            if not net.attrs.get("Internal"): self.logger.warning(f"{self.cfg.network} not internal")
        except docker.errors.NotFound:
            self.client.networks.create(self.cfg.network, driver="bridge", internal=True,
                ipam=docker.types.IPAMConfig(pool_configs=[docker.types.IPAMPool(subnet=self.cfg.network_subnet)]),
                options={"com.docker.network.bridge.enable_icc": "true"})

    def _login(self):
        try: self.client.login(username=self.cfg.dockerhub_username, password=self.cfg.dockerhub_password)
        except Exception as e: self.logger.warning(f"Login failed: {e}")

    def _check_size(self, image: str):
        if self.cfg.max_image_size_mb <= 0: return
        try:
            repo, tag = (image.split(":") + ["latest"])[:2]
            tok = _requests.get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull", timeout=10).json().get("token", "")
            r = _requests.get(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}", headers={"Authorization": f"Bearer {tok}", "Accept": "application/vnd.docker.distribution.manifest.v2+json"}, timeout=15)
            if r.status_code == 200:
                size = sum(l.get("size", 0) for l in r.json().get("layers", [])) // 1048576
                if size > self.cfg.max_image_size_mb: raise ValueError(f"Too large: {size}MB")
        except ValueError: raise
        except: pass

    def pull(self, image: str) -> bool:
        try: self._check_size(image)
        except Exception as e: self.logger.warning(e); return False
        for i in range(1, self.cfg.pull_retries + 1):
            try: self.client.images.pull(image); return True
            except Exception as e:
                msg = str(e).lower()
                if any(x in msg for x in ["429", "rate", "toomany"]): time.sleep(self.cfg.pull_retry_delay * i)
                elif "not found" in msg or "unknown" in msg: return False
                elif i < self.cfg.pull_retries: time.sleep(10)
                else: self.logger.error(f"Pull failed: {e}"); return False
        return False

    def run(self, image: str, name: str, ro: bool = True) -> str:
        opts = ["no-new-privileges:true"] if self.cfg.no_new_privileges else []
        caps = ["ALL"] if self.cfg.drop_all_caps else []
        ulim = [docker.types.Ulimit(name="nofile", soft=self.cfg.ulimit_nofile, hard=self.cfg.ulimit_nofile)]
        
        args = dict(image=image, name=name, detach=True, network=self.cfg.network, cap_drop=caps, security_opt=opts,
                    mem_limit=self.cfg.mem_limit, cpu_quota=self.cfg.cpu_quota, cpu_period=100000, pids_limit=self.cfg.pids_limit,
                    ulimits=ulim, read_only=ro, tmpfs=_TMPFS if ro else {}, environment={"VULNLAB_AUDIT": "true"})
        try: return self.client.containers.run(**args).id
        except Exception as e:
            err = str(e).lower()
            if ro and any(x in err for x in ["read-only", "readonly", "permission", "permitted"]):
                args.update(read_only=False, tmpfs={})
                return self.client.containers.run(**args).id
            raise

    def get_ip(self, cid: str) -> Optional[str]:
        try:
            c = self.client.containers.get(cid); c.reload()
            nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
            for n in (self.cfg.network, *nets.keys()):
                ip = nets.get(n, {}).get("IPAddress"); 
                if ip: return ip
        except: pass
        return None

    def probe(self, ip: str, timeout: int) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            for p in PROBE_PORTS:
                try:
                    with socket.create_connection((ip, p), 1): return True
                except: pass
            time.sleep(2)
        return False

    def stop_rm(self, cid: str):
        try:
            c = self.client.containers.get(cid)
            try: c.stop(timeout=self.cfg.stop_timeout)
            except: pass
            c.remove(force=True)
        except: pass

    @contextmanager
    def lifecycle(self, image: str) -> Iterator[Tuple[Optional[str], Optional[str], Optional[str]]]:
        name = f"ms_{re.sub(r'[^a-zA-Z0-9_.-]+', '_', image)[:40].strip('_')}_{uuid.uuid4().hex[:8]}"
        cid = None; ip = None; skip = None; stop_ev = threading.Event()
        try:
            with _API_SEM:
                if not self.pull(image): skip = "pull_failed"
                else: cid = self.run(image, name, self.cfg.read_only_rootfs)
            
            if cid:
                time.sleep(5)
                c = self.client.containers.get(cid); c.reload()
                if c.status != "running":
                    code = c.attrs.get("State", {}).get("ExitCode")
                    # Capture exit logs for auditability before any retry
                    try:
                        exit_logs = c.logs(tail=100, timestamps=True).decode("utf-8", errors="replace").strip()
                        if exit_logs:
                            self.logger.warning(f"[EXIT-LOG] {image} exited:{code} stdout/stderr:\n{exit_logs}")
                    except Exception: pass
                    # Fallback to RW if exited with typical permission/read-only codes
                    if self.cfg.read_only_rootfs and code in [1, 126, 127]:
                        self.logger.info(f"Retrying {image} in RW mode (exited with {code})")
                        self.stop_rm(cid); cid = self.run(image, name + "_rw", False)
                        c = self.client.containers.get(cid); c.reload()

                    if c.status != "running":
                        # Capture RW retry exit logs too
                        try:
                            exit_logs = c.logs(tail=100, timestamps=True).decode("utf-8", errors="replace").strip()
                            if exit_logs:
                                self.logger.warning(f"[EXIT-LOG-RW] {image} exited:{code} stdout/stderr:\n{exit_logs}")
                        except Exception: pass
                        skip = f"exited:{code}"; self.stop_rm(cid); cid = None
                
                if cid:
                    time.sleep(max(0, self.cfg.startup_wait - 5))
                    c.reload()
                    if c.status != "running": skip = "exited_startup"; cid = None
                    else:
                        ip = self.get_ip(cid)
                        if not ip: skip = "no_ip"; cid = None
                        else: self.probe(ip, self.cfg.health_timeout)
            
            yield ip, cid, skip
        except Exception as e: self.logger.error(f"Lifecycle error: {e}"); yield None, None, str(e)
        finally:
            if cid: self.stop_rm(cid)
            with self._lock:
                self._scan_count += 1
                if self.cfg.remove_image_after:
                    try: self.client.images.remove(image, force=True)
                    except: pass
                if self._scan_count % self.cfg.prune_every == 0:
                    try: self.client.containers.prune(); self.client.images.prune(filters={"dangling": True})
                    except: pass
