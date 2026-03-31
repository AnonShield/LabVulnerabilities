"""
container.py — Secure, resilient Docker lifecycle for mass scanning.

Security model (defence-in-depth for arbitrary untrusted images):
  - No privileged mode, no host-network, no volume mounts
  - All Linux capabilities dropped (cap-drop ALL)
  - no-new-privileges prevents setuid escalation
  - PID limit prevents fork bombs
  - Memory + CPU limits prevent resource exhaustion
  - Read-only rootfs with tmpfs overlays for required write paths
  - Isolated network — scanned containers cannot reach the host or internet
  - Every operation has an explicit timeout; nothing blocks forever
  - Container is always removed in the finally block (leak-proof)
  - Watchdog thread detects if container dies mid-scan
"""
import logging
import socket
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

import docker
import docker.errors
import docker.types
import requests as _requests


# ---------------------------------------------------------------------------
# Probe ports — ordered by likelihood of being open
# ---------------------------------------------------------------------------
PROBE_PORTS: Tuple[int, ...] = (
    80, 443, 8080, 8443, 8888, 8000, 3000, 5000,   # HTTP(S)
    22, 21, 23,                                      # SSH/FTP/Telnet
    3306, 5432, 27017, 6379, 9200, 5601,            # Databases
    8161, 15672, 5672, 9092, 2181,                  # MQ/Kafka
    9090, 3100, 9093, 9094,                         # Monitoring
)

# tmpfs mounts — common paths that services need to write to.
# noexec prevents running binaries from these dirs.
_TMPFS_MOUNTS = {
    "/tmp":     "rw,noexec,nosuid,size=64m",
    "/run":     "rw,noexec,nosuid,size=32m",
    "/var/run": "rw,noexec,nosuid,size=32m",
}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ContainerConfig:
    network:              str   = "trabalho_vulnnet"
    network_subnet:       str   = "172.30.0.0/16"

    # Timing
    startup_wait:         int   = 15    # seconds after run before first probe
    health_timeout:       int   = 90    # max wait for any port to open
    scan_watchdog:        int   = 3600  # kill container if scan takes longer (1h)
    stop_timeout:         int   = 10    # docker stop timeout

    # Pull
    pull_retries:         int   = 3
    pull_retry_delay:     int   = 60    # rate-limit back-off
    max_image_size_mb:    int   = 10240 # skip images larger than 10 GB
    dockerhub_username:   str   = ""
    dockerhub_password:   str   = ""

    # Resource limits (prevent container DoS on host)
    mem_limit:            str   = "512m"
    cpu_quota:            int   = 100000   # 1 CPU (100000 / 100000)
    pids_limit:           int   = 256      # fork-bomb prevention
    ulimit_nofile:        int   = 1024     # fd limit

    # Security
    read_only_rootfs:     bool  = True     # read-only FS + tmpfs overlays
    drop_all_caps:        bool  = True     # cap-drop ALL
    no_new_privileges:    bool  = True     # no setuid escalation

    # Cleanup
    remove_image_after:   bool  = True
    prune_every:          int   = 20


# ---------------------------------------------------------------------------
# Failure reasons (structured, not just strings)
# ---------------------------------------------------------------------------

class ContainerError(Exception):
    """Raised when a container cannot be used for scanning."""

class PullError(ContainerError):
    pass

class ImageTooLargeError(ContainerError):
    pass

class ContainerExitedError(ContainerError):
    pass

class NoOpenPortError(ContainerError):
    """Container started but no port responded — GVM will still scan (ICMP/OS detection)."""

class WatchdogKillError(ContainerError):
    """Watchdog killed the container — scan took too long."""


# ---------------------------------------------------------------------------
# ContainerManager
# ---------------------------------------------------------------------------

# Global throttle for heavy Docker operations (Pull/Run)
# This prevents the Docker Daemon from being saturated by 40+ concurrent requests.
_DOCKER_API_SEMAPHORE = threading.Semaphore(5)

class ContainerManager:
    def __init__(self, cfg: ContainerConfig, logger: logging.Logger):
        self.cfg    = cfg
        self.logger = logger
        self._scan_count   = 0
        self._count_lock   = threading.Lock()

        try:
            # Increased timeout to 300s and explicit retries for socket stability
            self.client = docker.from_env(timeout=300)
            self.client.ping()
        except docker.errors.DockerException as e:
            raise RuntimeError(f"Docker not available: {e}") from e

        self._ensure_network()

        if cfg.dockerhub_username and cfg.dockerhub_password:
            self._login_dockerhub()

    # ------------------------------------------------------------------
    # Network setup
    # ------------------------------------------------------------------

    def _ensure_network(self):
        """
        Ensure the scan network exists and is internal (air-gapped).
        EnvironmentSetup handles first-time creation; this is a safety net
        in case ContainerManager starts before EnvironmentSetup runs.
        """
        net = None
        try:
            net = self.client.networks.get(self.cfg.network)
        except docker.errors.NotFound:
            pass

        if net is not None:
            if not net.attrs.get("Internal", False):
                self.logger.warning(
                    f"Scan network '{self.cfg.network}' is not internal — "
                    "outbound internet access is NOT blocked. "
                    "Run EnvironmentSetup to recreate it securely."
                )
            return

        self.logger.info(f"Creating air-gapped scan network '{self.cfg.network}' (internal=True)…")
        self.client.networks.create(
            self.cfg.network,
            driver="bridge",
            internal=True,
            ipam=docker.types.IPAMConfig(
                pool_configs=[docker.types.IPAMPool(subnet=self.cfg.network_subnet)]
            ),
            options={"com.docker.network.bridge.enable_icc": "true"},
        )

    # ------------------------------------------------------------------
    # DockerHub auth (free account = 200 pulls/6h per machine)
    # ------------------------------------------------------------------

    def _login_dockerhub(self):
        try:
            self.client.login(
                username=self.cfg.dockerhub_username,
                password=self.cfg.dockerhub_password,
            )
            self.logger.info(f"DockerHub: logged in as '{self.cfg.dockerhub_username}'")
        except Exception as e:
            self.logger.warning(f"DockerHub login failed: {e} — using anonymous (100 pulls/6h)")

    # ------------------------------------------------------------------
    # Image pre-flight check (size gate before pulling)
    # ------------------------------------------------------------------

    def _check_image_size(self, image: str) -> Optional[int]:
        """
        Query the registry manifest to get compressed size before pulling.
        Returns size in MB or None if check is not available.
        Raises ImageTooLargeError if over the configured limit.
        """
        if self.cfg.max_image_size_mb <= 0:
            return None
        try:
            repo, tag = (image.split(":") + ["latest"])[:2]
            # DockerHub token fetch
            tok_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
            tok = _requests.get(tok_url, timeout=10).json().get("token", "")
            headers = {"Authorization": f"Bearer {tok}"}
            # Fetch manifest list to get layer sizes
            manifest_url = f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}"
            headers["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"
            r = _requests.get(manifest_url, headers=headers, timeout=15)
            if r.status_code != 200:
                return None
            layers = r.json().get("layers", [])
            size_mb = sum(l.get("size", 0) for l in layers) // (1024 * 1024)
            if size_mb > self.cfg.max_image_size_mb:
                raise ImageTooLargeError(
                    f"Image {image} is ~{size_mb} MB > limit {self.cfg.max_image_size_mb} MB"
                )
            return size_mb
        except ImageTooLargeError:
            raise
        except Exception:
            return None   # size check failed — allow pull anyway

    # ------------------------------------------------------------------
    # Pull
    # ------------------------------------------------------------------

    def pull(self, image: str) -> bool:
        """Pull with retry, rate-limit back-off, and size gate."""
        try:
            self._check_image_size(image)
        except ImageTooLargeError as e:
            self.logger.warning(f"[SKIP] {e}")
            return False

        for attempt in range(1, self.cfg.pull_retries + 1):
            try:
                self.client.images.pull(image)
                return True
            except docker.errors.ImageNotFound:
                self.logger.error(f"[PULL] Image not found on registry: {image}")
                return False
            except docker.errors.APIError as e:
                msg = str(e).lower()
                if "toomanyrequests" in msg or "429" in msg or "rate" in msg:
                    delay = self.cfg.pull_retry_delay * attempt
                    self.logger.warning(
                        f"[PULL] Rate-limited for {image}. "
                        f"Waiting {delay}s (attempt {attempt}/{self.cfg.pull_retries})"
                    )
                    time.sleep(delay)
                elif "manifest unknown" in msg or "not found" in msg:
                    self.logger.error(f"[PULL] Manifest not found: {image}")
                    return False
                elif attempt < self.cfg.pull_retries:
                    self.logger.warning(f"[PULL] Error pulling {image}: {e} — retry {attempt}")
                    time.sleep(10)
                else:
                    raise PullError(f"Pull failed after {attempt} attempts: {e}") from e
            except Exception as e:
                if attempt < self.cfg.pull_retries:
                    self.logger.warning(f"[PULL] Unexpected error for {image}: {e} — retry")
                    time.sleep(10)
                else:
                    raise PullError(str(e)) from e
        return False

    # ------------------------------------------------------------------
    # Run (hardened)
    # ------------------------------------------------------------------

    def run(self, image: str, name: str) -> str:
        """
        Start container with full security hardening.
        Returns container ID.
        """
        security_opts: List[str] = []
        if self.cfg.no_new_privileges:
            security_opts.append("no-new-privileges:true")

        cap_drop = ["ALL"] if self.cfg.drop_all_caps else []

        ulimits = [docker.types.Ulimit(name="nofile",
                                       soft=self.cfg.ulimit_nofile,
                                       hard=self.cfg.ulimit_nofile)]

        kwargs: dict = dict(
            image          = image,
            name           = name,
            detach         = True,
            network        = self.cfg.network,
            # NO volumes, NO privileged, NO host-network
            privileged     = False,
            cap_drop       = cap_drop,
            security_opt   = security_opts,
            mem_limit      = self.cfg.mem_limit,
            cpu_quota      = self.cfg.cpu_quota,
            cpu_period     = 100000,
            pids_limit     = self.cfg.pids_limit,
            ulimits        = ulimits,
            # Prevent writing to container root FS (forces use of tmpfs mounts)
            read_only      = self.cfg.read_only_rootfs,
            tmpfs          = _TMPFS_MOUNTS if self.cfg.read_only_rootfs else {},
            # No stdin, no TTY — non-interactive
            stdin_open     = False,
            tty            = False,
            environment    = {"VULNLAB_AUDIT": "true"},
        )

        try:
            container = self.client.containers.run(**kwargs)
            return container.id
        except docker.errors.APIError as e:
            msg = str(e).lower()
            # Some images explicitly require privileged or specific mounts.
            # If they fail with read_only, retry without it — still keep caps/limits.
            if self.cfg.read_only_rootfs and ("read-only" in msg or "readonly" in msg
                                              or "read only" in msg):
                self.logger.debug(f"[RUN] {image} failed with read-only FS, retrying writable…")
                kwargs["read_only"] = False
                kwargs["tmpfs"]     = {}
                container = self.client.containers.run(**kwargs)
                return container.id
            raise

    # ------------------------------------------------------------------
    # Container state checks
    # ------------------------------------------------------------------

    def get_ip(self, container_id: str) -> Optional[str]:
        try:
            c = self.client.containers.get(container_id)
            c.reload()
            nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
            for net_name in (self.cfg.network, *nets.keys()):
                ip = nets.get(net_name, {}).get("IPAddress", "")
                if ip:
                    return ip
        except Exception as e:
            self.logger.debug(f"get_ip({container_id[:12]}): {e}")
        return None

    def is_running(self, container_id: str) -> bool:
        try:
            c = self.client.containers.get(container_id)
            c.reload()
            return c.status == "running"
        except Exception:
            return False

    def get_exit_code(self, container_id: str) -> Optional[int]:
        try:
            c = self.client.containers.get(container_id)
            c.reload()
            return c.attrs.get("State", {}).get("ExitCode")
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Port probe
    # ------------------------------------------------------------------

    def probe_reachable(self, ip: str, timeout: int) -> bool:
        """
        Try TCP connect on each probe port until one responds.
        Returns True as soon as any port is open.
        Returns False after timeout — container is still scanned (GVM does ICMP/OS detect).
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            for port in PROBE_PORTS:
                try:
                    with socket.create_connection((ip, port), timeout=1):
                        self.logger.debug(f"Port {port} open on {ip}")
                        return True
                except (ConnectionRefusedError, OSError):
                    pass
            # Check container is still alive between rounds
            time.sleep(2)
        return False

    # ------------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------------

    def start_watchdog(self, container_id: str, stop_event: threading.Event) -> threading.Thread:
        """
        Background thread: kills container if it runs longer than scan_watchdog seconds.
        Also kills if container exits unexpectedly during scan (crash detection).
        """
        def _watch():
            deadline = time.time() + self.cfg.scan_watchdog
            while not stop_event.wait(10):
                if time.time() > deadline:
                    self.logger.warning(
                        f"[WATCHDOG] Container {container_id[:12]} exceeded "
                        f"{self.cfg.scan_watchdog}s limit — killing"
                    )
                    self.stop_remove(container_id)
                    stop_event.set()
                    return
                if not self.is_running(container_id):
                    self.logger.warning(
                        f"[WATCHDOG] Container {container_id[:12]} exited unexpectedly"
                    )
                    stop_event.set()
                    return

        t = threading.Thread(target=_watch, daemon=True)
        t.start()
        return t

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def stop_remove(self, container_id: str):
        try:
            c = self.client.containers.get(container_id)
            c.stop(timeout=self.cfg.stop_timeout)
            c.remove(force=True)
        except docker.errors.NotFound:
            pass
        except Exception as e:
            self.logger.debug(f"stop_remove({container_id[:12]}): {e}")
            # Force remove even if stop failed
            try:
                self.client.api.remove_container(container_id, force=True)
            except Exception:
                pass

    def remove_image(self, image: str):
        try:
            self.client.images.remove(image, force=True)
        except docker.errors.ImageNotFound:
            pass
        except Exception as e:
            self.logger.debug(f"remove_image({image}): {e}")

    def _post_scan_cleanup(self, image: str):
        with self._count_lock:
            self._scan_count += 1
            count = self._scan_count

        if self.cfg.remove_image_after:
            self.remove_image(image)

        if count % self.cfg.prune_every == 0:
            try:
                self.client.containers.prune()
                self.client.images.prune(filters={"dangling": True})
                self.logger.debug(f"Pruned after {count} scans")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Full lifecycle context manager
    # ------------------------------------------------------------------

    @contextmanager
    def lifecycle(self, image: str) -> Iterator[Tuple[Optional[str], Optional[str]]]:
        """
        Full secure lifecycle:
          size-check → pull → run (hardened) → wait → IP → probe → yield (ip, container_id)
          → stop → remove → cleanup

        Yields (ip, container_id) or (None, None) on any failure.
        Container is ALWAYS removed in finally — no leaks.

        IMPORTANT: single yield point — avoids 'generator didn't stop after throw()'
        which would defer container cleanup to GC instead of running it immediately.
        """
        safe_name = _safe_container_name(image)
        container_id: Optional[str] = None
        result_ip: Optional[str] = None
        watchdog_stop = threading.Event()

        try:
            # All setup runs before the yield so exceptions here don't re-enter
            # the generator after it has already yielded (which breaks @contextmanager).
            try:
                with _DOCKER_API_SEMAPHORE:
                    if not self.pull(image):
                        self.logger.warning(f"[SKIP] {image}: pull failed / not found")
                    else:
                        container_id = self.run(image, safe_name)

                if container_id:
                    time.sleep(min(self.cfg.startup_wait, 5))
                    if not self.is_running(container_id):
                        code = self.get_exit_code(container_id)
                        self.logger.warning(
                            f"[SKIP] {image}: Container exited immediately "
                            f"(code={code}) — not a service image"
                        )
                        container_id = None
                    else:
                        remaining = max(0, self.cfg.startup_wait - 5)
                        if remaining:
                            time.sleep(remaining)

                        if not self.is_running(container_id):
                            code = self.get_exit_code(container_id)
                            self.logger.warning(
                                f"[SKIP] {image}: Container exited during startup (code={code})"
                            )
                        else:
                            ip = self.get_ip(container_id)
                            if not ip:
                                self.logger.warning(f"[SKIP] {image}: Container has no IP")
                            else:
                                has_port = self.probe_reachable(ip, self.cfg.health_timeout)
                                if not has_port:
                                    self.logger.info(
                                        f"[{image}] No open port found on {ip} — "
                                        "GVM will still run OS/ICMP detection"
                                    )
                                self.start_watchdog(container_id, watchdog_stop)
                                result_ip = ip

            except (ImageTooLargeError, PullError) as e:
                self.logger.warning(f"[SKIP] {image}: {e}")
            except docker.errors.APIError as e:
                self.logger.error(f"[DOCKER] {image}: {e}")
            except Exception as e:
                self.logger.error(f"[CONTAINER] Unexpected error for {image}: {e}")

            # Single yield — container cleanup always runs in finally below.
            yield result_ip, container_id

        finally:
            watchdog_stop.set()
            if container_id:
                self.stop_remove(container_id)
            self._post_scan_cleanup(image)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_container_name(image: str) -> str:
    """
    Generate a unique, Docker-valid container name.
    Docker names: [a-zA-Z0-9][a-zA-Z0-9_.-]*
    Max 63 chars to stay well within limits.
    UUID suffix guarantees uniqueness even if image is scanned twice.
    """
    import re
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", image)[:40].strip("_.")
    uid  = uuid.uuid4().hex[:8]
    return f"ms_{slug}_{uid}"
