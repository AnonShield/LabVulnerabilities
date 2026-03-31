"""
Auto-setup for mass scanning:
  1. Create isolated Docker network (if absent)
  2. Start OpenVAS container with GVM bound to 127.0.0.1 ONLY
  3. Connect OpenVAS to the scan network (so it can reach target containers)
  4. Wait for GVM to become responsive

Security posture:
  - GVM port 9390 is bound to 127.0.0.1 only — unreachable from the network
  - Scanned containers have NO host port mappings — isolated network only
  - OpenVAS container has no privileged flags, no host-network mode
  - Network is a dedicated bridge — scanned containers cannot reach host services
"""
import logging
import time
from dataclasses import dataclass
import docker
import docker.errors
import docker.types


OPENVAS_IMAGE   = "immauss/openvas:latest"
CONTAINER_NAME  = "openvas_massscan"
GVM_INNER_PORT  = 9390   # GMP API port (9392 is the HTTPS web UI)
# Bind ONLY to loopback — no network exposure
GVM_BIND_HOST   = "127.0.0.1"


@dataclass
class SetupConfig:
    network:          str  = "trabalho_vulnnet"
    network_subnet:   str  = "172.30.0.0/16"
    openvas_image:    str  = OPENVAS_IMAGE
    container_name:   str  = CONTAINER_NAME
    gvm_password:     str  = "admin"
    gvm_port:         int  = GVM_INNER_PORT
    startup_timeout:  int  = 3600  # 1 hour to wait for GVM to be ready (first run sync)
    skip_openvas:     bool = False  # set True if OpenVAS is managed externally


class EnvironmentSetup:
    """
    Idempotent setup — safe to call on every run.
    If everything is already ready, it returns immediately.
    """

    def __init__(self, cfg: SetupConfig, logger: logging.Logger):
        self.cfg = cfg
        self.logger = logger
        try:
            self.client = docker.from_env()
        except docker.errors.DockerException as e:
            raise RuntimeError(f"Docker not available: {e}") from e

    def run(self) -> str:
        """
        Ensure the environment is ready.
        Returns the GVM connection string "127.0.0.1:<port>".
        """
        self._ensure_network()
        if not self.cfg.skip_openvas:
            container = self._get_container()
            if container and container.status == "running":
                import socket as _sock
                try:
                    with _sock.create_connection((GVM_BIND_HOST, self.cfg.gvm_port), timeout=2):
                        self.logger.info("OpenVAS already running and responsive.")
                        # Still must ensure OpenVAS is on the scan network —
                        # the network may have been recreated since last start.
                        self._connect_to_scan_network(container)
                        return f"127.0.0.1:{self.cfg.gvm_port}"
                except OSError:
                    pass  # not responsive yet — fall through to full setup
            self._ensure_openvas()
        return f"127.0.0.1:{self.cfg.gvm_port}"

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def _ensure_network(self):
        """
        Create or verify the scan network.

        Security properties:
          internal=True          — no default gateway, no outbound internet access.
                                   Containers cannot exfiltrate data or phone home.
          enable_icc=true        — OpenVAS must reach scan targets on the same network.
          enable_ip_masquerade   — irrelevant with internal=True (no external routing).

        OpenVAS is safe: it is connected to both this network AND the default bridge,
        so it retains internet access for NVT feeds while scan targets are fully air-gapped.
        """
        net = None
        try:
            net = self.client.networks.get(self.cfg.network)
        except docker.errors.NotFound:
            pass

        # If the network exists but is NOT internal, recreate it securely.
        if net is not None:
            is_internal = net.attrs.get("Internal", False)
            if not is_internal:
                self.logger.warning(
                    f"Network '{self.cfg.network}' exists but is NOT internal — "
                    "recreating with internal=True to block container internet access."
                )
                try:
                    net.remove()
                except Exception as e:
                    self.logger.error(
                        f"Could not remove non-internal network: {e}. "
                        "Stop all containers on this network first, then restart."
                    )
                    return
                net = None
            else:
                self.logger.debug(f"Network '{self.cfg.network}' already exists (internal=True)")
                return

        self.logger.info(
            f"Creating air-gapped scan network '{self.cfg.network}' "
            f"({self.cfg.network_subnet}, internal=True)…"
        )
        self.client.networks.create(
            self.cfg.network,
            driver="bridge",
            internal=True,          # ← no outbound internet for scan targets
            ipam=docker.types.IPAMConfig(
                pool_configs=[docker.types.IPAMPool(subnet=self.cfg.network_subnet)]
            ),
            options={
                "com.docker.network.bridge.enable_icc": "true",  # OpenVAS ↔ targets
            },
        )
        self.logger.info(f"Network '{self.cfg.network}' created (air-gapped)")

    # ------------------------------------------------------------------
    # OpenVAS
    # ------------------------------------------------------------------

    def _ensure_openvas(self):
        container = self._get_container()

        if container is None:
            self.logger.info(f"Starting OpenVAS container '{self.cfg.container_name}'…")
            self.logger.info(f"  image  : {self.cfg.openvas_image}")
            self.logger.info(f"  GVM    : {GVM_BIND_HOST}:{self.cfg.gvm_port} (localhost only — no network exposure)")
            self.logger.info(f"  network: {self.cfg.network}")
            container = self._start_openvas()
        elif container.status != "running":  # type: ignore[union-attr]
            self.logger.info("Restarting OpenVAS container…")
            container.start()  # type: ignore[union-attr]
        else:
            self.logger.debug("OpenVAS container already running")

        self._connect_to_scan_network(container)
        self._wait_for_gvm()

    def _get_container(self):
        try:
            return self.client.containers.get(self.cfg.container_name)
        except docker.errors.NotFound:
            return None

    def _start_openvas(self):
        try:
            self.client.images.get(self.cfg.openvas_image)
        except docker.errors.ImageNotFound:
            self.logger.info(f"Pulling {self.cfg.openvas_image} (first time only)…")
            self.client.images.pull(self.cfg.openvas_image)

        # Use low-level API for full control over port binding and restart policy
        host_cfg = self.client.api.create_host_config(
            port_bindings={
                # SECURITY: bind ONLY to 127.0.0.1 — never exposed to network
                f"{GVM_INNER_PORT}/tcp": [(GVM_BIND_HOST, self.cfg.gvm_port)]
            },
            restart_policy={"Name": "unless-stopped"},
        )
        resp = self.client.api.create_container(
            self.cfg.openvas_image,
            name=self.cfg.container_name,
            detach=True,
            ports=[GVM_INNER_PORT],
            environment={
                "PASSWORD": self.cfg.gvm_password,
                "GMP": str(GVM_INNER_PORT)
            },
            host_config=host_cfg,
        )
        self.client.api.start(resp["Id"])
        container = self.client.containers.get(resp["Id"])
        self.logger.info(f"OpenVAS container started (id={container.short_id})")
        return container

    def _connect_to_scan_network(self, container):
        """Connect OpenVAS to the scan network so it can reach target containers."""
        network = self.client.networks.get(self.cfg.network)
        container.reload()  # type: ignore[union-attr]
        connected = set(
            container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys()  # type: ignore[union-attr]
        )
        if self.cfg.network not in connected:
            self.logger.info(f"Connecting OpenVAS to network '{self.cfg.network}'…")
            network.connect(container)
        else:
            self.logger.debug(f"OpenVAS already on network '{self.cfg.network}'")

    def _wait_for_gvm(self):
        """Poll until GVM responds on 127.0.0.1:port."""
        import socket as _sock
        self.logger.info(f"Waiting for GVM on {GVM_BIND_HOST}:{self.cfg.gvm_port} (timeout={self.cfg.startup_timeout}s)…")
        deadline = time.time() + self.cfg.startup_timeout
        interval = 10
        while time.time() < deadline:
            try:
                with _sock.create_connection((GVM_BIND_HOST, self.cfg.gvm_port), timeout=5):
                    self.logger.info("GVM is ready")
                    return
            except OSError:
                remaining = int(deadline - time.time())
                self.logger.info(f"  GVM not ready yet — retrying in {interval}s ({remaining}s left)…")
                time.sleep(interval)
        raise TimeoutError(
            f"GVM did not become ready within {self.cfg.startup_timeout}s. "
            f"Check: docker logs {self.cfg.container_name}"
        )
