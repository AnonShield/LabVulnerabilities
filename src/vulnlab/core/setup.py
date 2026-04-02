import logging
import time
import socket as _sock
from dataclasses import dataclass
import docker
import docker.errors
import docker.types

OPENVAS_IMAGE  = "immauss/openvas:latest"
GVM_INNER_PORT = 9390
GVM_BIND_HOST  = "127.0.0.1"

@dataclass
class SetupConfig:
    network:         str  = "trabalho_vulnnet"
    network_subnet:  str  = "172.30.0.0/16"
    openvas_image:   str  = OPENVAS_IMAGE
    container_name:  str  = "openvas_massscan"
    gvm_password:    str  = "admin"
    gvm_port:        int  = GVM_INNER_PORT
    startup_timeout: int  = 3600
    skip_openvas:    bool = False

class EnvironmentSetup:
    def __init__(self, cfg: SetupConfig, logger: logging.Logger):
        self.cfg, self.logger = cfg, logger
        try:
            self.client = docker.from_env()
        except Exception as e:
            raise RuntimeError(f"Docker error: {e}")

    def run(self) -> str:
        self._ensure_net()
        if not self.cfg.skip_openvas:
            c = self._get_c()
            if c and c.status == "running":
                try:
                    with _sock.create_connection((GVM_BIND_HOST, self.cfg.gvm_port), 2):
                        self.logger.info("GVM ready.")
                        self._connect(c)
                        return f"127.0.0.1:{self.cfg.gvm_port}"
                except OSError: pass
            self._ensure_openvas()
        return f"127.0.0.1:{self.cfg.gvm_port}"

    def _ensure_net(self):
        try:
            net = self.client.networks.get(self.cfg.network)
            if not net.attrs.get("Internal", False):
                self.logger.warning(f"Recreating {self.cfg.network} as internal...")
                net.remove()
                raise docker.errors.NotFound("recreate")
        except docker.errors.NotFound:
            self.client.networks.create(
                self.cfg.network, driver="bridge", internal=True,
                ipam=docker.types.IPAMConfig(pool_configs=[docker.types.IPAMPool(subnet=self.cfg.network_subnet)]),
                options={"com.docker.network.bridge.enable_icc": "true"}
            )

    def _ensure_openvas(self):
        c = self._get_c()
        if not c:
            try: self.client.images.get(self.cfg.openvas_image)
            except docker.errors.ImageNotFound:
                self.logger.info(f"Pulling {self.cfg.openvas_image}...")
                self.client.images.pull(self.cfg.openvas_image)
            
            h_cfg = self.client.api.create_host_config(
                port_bindings={f"{GVM_INNER_PORT}/tcp": [(GVM_BIND_HOST, self.cfg.gvm_port)]},
                restart_policy={"Name": "unless-stopped"}
            )
            resp = self.client.api.create_container(
                self.cfg.openvas_image, name=self.cfg.container_name, detach=True,
                ports=[GVM_INNER_PORT], host_config=h_cfg,
                environment={"PASSWORD": self.cfg.gvm_password, "GMP": str(GVM_INNER_PORT), "SKIPSYNC": "true"}
            )
            self.client.api.start(resp["Id"])
            c = self.client.containers.get(resp["Id"])
        elif c.status != "running":
            c.start()
        
        self._connect(c)
        self._wait_gvm()
        try: c.exec_run("/scripts/sync.sh")
        except: pass

    def _get_c(self):
        try: return self.client.containers.get(self.cfg.container_name)
        except: return None

    def _connect(self, c):
        net = self.client.networks.get(self.cfg.network)
        c.reload()
        if self.cfg.network not in c.attrs.get("NetworkSettings", {}).get("Networks", {}):
            net.connect(c)

    def _wait_gvm(self):
        deadline = time.time() + self.cfg.startup_timeout
        while time.time() < deadline:
            try:
                with _sock.create_connection((GVM_BIND_HOST, self.cfg.gvm_port), 5): return
            except OSError:
                time.sleep(10)
        raise TimeoutError("GVM timeout")
