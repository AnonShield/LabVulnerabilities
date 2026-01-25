#!/usr/bin/env python3
"""
OpenVAS Automated Scanner - VulnLab Integration
Escaneia IPs sequencialmente e baixa relatórios automaticamente.

Autor: VulnLab Project
Versão: 2.0.0
"""

import argparse
import json
import logging
import re
import signal
import sys
import time
from base64 import b64decode
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

try:
    import yaml
except ImportError:
    yaml = None

try:
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
except ImportError:
    print("\n[ERRO] gvm-tools não instalado. Execute:")
    print("  pip3 install gvm-tools")
    print("\nOu use o script de instalação:")
    print("  ./setup.sh")
    sys.exit(1)


# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

@dataclass
class Config:
    """Configuração do scanner OpenVAS."""
    # Conexão GVM
    host: str = "127.0.0.1"
    port: int = 9390
    username: str = "admin"
    password: str = "admin"

    # Scan
    scan_config_name: str = "Full and fast"
    port_list_name: str = "All TCP and Nmap top 100 UDP"
    scanner_name: str = "OpenVAS Default"

    # Relatórios
    report_formats: List[str] = field(default_factory=lambda: ["PDF", "XML", "CSV", "TXT"])

    # Diretórios
    output_dir: str = "./reports"
    state_file: str = "./scanner_state.json"

    # Comportamento
    cleanup_after_scan: bool = False
    retry_attempts: int = 3
    retry_delay: int = 10
    poll_interval: int = 30
    connection_timeout: int = 120
    service_name: Optional[str] = None

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Carrega configuração de arquivo YAML."""
        if yaml is None:
            logging.warning("PyYAML não instalado, usando configuração padrão")
            return cls()
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if data:
                return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
            return cls()
        except FileNotFoundError:
            return cls()


class ScanStatus(Enum):
    """Status possíveis de um scan."""
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    STOPPED = "stopped"


# ============================================================================
# LOGGING
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Formatter com cores para o terminal."""
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configura logging com cores e arquivo."""
    logger = logging.getLogger("openvas_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(ColoredFormatter(
        '%(asctime)s │ %(levelname)-17s │ %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger.addHandler(console)

    log_dir = Path("./logs")
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.FileHandler(
        log_dir / f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s'
    ))
    logger.addHandler(file_handler)

    return logger


# ============================================================================
# ESTADO PERSISTENTE
# ============================================================================

@dataclass
class ScanResult:
    """Resultado de um scan individual."""
    ip: str
    status: str
    task_id: Optional[str] = None
    target_id: Optional[str] = None
    report_id: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    reports_downloaded: List[str] = field(default_factory=list)
    error: Optional[str] = None
    vulnerabilities: Dict[str, int] = field(default_factory=dict)


class StateManager:
    """Gerencia estado persistente para permitir retomada."""

    def __init__(self, state_file: str):
        self.state_file = Path(state_file)
        self.state = self._load()

    def _load(self) -> dict:
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {"scans": {}, "session_start": None}
        return {"scans": {}, "session_start": None}

    def save(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2, default=str)

    def get_scan(self, ip: str) -> Optional[ScanResult]:
        if ip in self.state["scans"]:
            return ScanResult(**self.state["scans"][ip])
        return None

    def set_scan(self, result: ScanResult):
        self.state["scans"][result.ip] = result.__dict__
        self.save()

    def is_completed(self, ip: str) -> bool:
        scan = self.get_scan(ip)
        return scan is not None and scan.status == "done" and scan.reports_downloaded

    def get_pending_ips(self, all_ips: list) -> list:
        return [ip for ip in all_ips if not self.is_completed(ip)]

    def start_session(self):
        if not self.state["session_start"]:
            self.state["session_start"] = datetime.now().isoformat()
            self.save()

    def get_summary(self) -> dict:
        scans = self.state["scans"]
        return {
            "total": len(scans),
            "done": sum(1 for s in scans.values() if s.get("status") == "done"),
            "failed": sum(1 for s in scans.values() if s.get("status") == "failed"),
            "pending": sum(1 for s in scans.values() if s.get("status") == "pending"),
        }


# ============================================================================
# CLIENTE GVM
# ============================================================================

class GVMClient:
    """Cliente para comunicação com o Greenbone Vulnerability Manager."""

    REPORT_FORMAT_IDS = {
        "PDF": "c402cc3e-b531-11e1-9163-406186ea4fc5",
        "XML": "a994b278-1f62-11e1-96ac-406186ea4fc5",
        "CSV": "c1645568-627a-11e3-a660-406186ea4fc5",
        "TXT": "a3810a62-1f62-11e1-9219-406186ea4fc5",
        "HTML": "6c248850-1f62-11e1-b082-406186ea4fc5",
    }

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.transform = EtreeTransform()
        self._cache: Dict[str, Any] = {}
        self._connected = False

    @contextmanager
    def _get_gmp(self):
        """Context manager para obter conexão GMP autenticada."""
        connection = TLSConnection(
            hostname=self.config.host,
            port=self.config.port,
            timeout=self.config.connection_timeout
        )
        with Gmp(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.config.username, self.config.password)
            yield gmp

    def wait_for_gvm(self, max_wait: int = 600) -> bool:
        """Aguarda GVM ficar disponível."""
        start = time.time()

        while time.time() - start < max_wait:
            try:
                self.logger.info(f"Tentando conectar ao GVM em {self.config.host}:{self.config.port}...")

                with self._get_gmp() as gmp:
                    version = gmp.get_version()
                    gmp_version = version.find("version").text
                    self.logger.info(f"Conectado! GMP versão: {gmp_version}")

                    self._cache_ids(gmp)
                    self._connected = True
                    return True

            except ConnectionResetError:
                self.logger.warning("GVM ainda inicializando. Aguardando 30s...")
                time.sleep(30)
            except Exception as e:
                self.logger.warning(f"Erro de conexão: {e}. Tentando novamente em 10s...")
                time.sleep(10)

        self.logger.error("Timeout aguardando GVM ficar disponível")
        return False

    def _cache_ids(self, gmp):
        """Faz cache dos IDs necessários."""
        self.logger.debug("Carregando configurações do GVM...")

        # Scan configs
        configs = gmp.get_scan_configs()
        for config in configs.findall(".//config"):
            name = config.find("name").text
            if name and "full and fast" in name.lower():
                self._cache["scan_config_id"] = config.get("id")
                self.logger.debug(f"Usando scan config: {name}")
                break

        # Port lists
        port_lists = gmp.get_port_lists()
        for pl in port_lists.findall(".//port_list"):
            name = pl.find("name").text
            if name and "all tcp" in name.lower():
                self._cache["port_list_id"] = pl.get("id")
                self.logger.debug(f"Usando port list: {name}")
                break

        # Scanners
        scanners = gmp.get_scanners()
        for scanner in scanners.findall(".//scanner"):
            name = scanner.find("name").text
            if name and "openvas" in name.lower():
                self._cache["scanner_id"] = scanner.get("id")
                self.logger.debug(f"Usando scanner: {name}")
                break

        # Report formats
        formats = gmp.get_report_formats()
        self._cache["report_formats"] = {}
        for fmt in formats.findall(".//report_format"):
            name = fmt.find("name").text
            if name:
                self._cache["report_formats"][name.upper()] = fmt.get("id")

        required = ["scan_config_id", "port_list_id", "scanner_id"]
        missing = [k for k in required if k not in self._cache]
        if missing:
            raise RuntimeError(f"Configurações não encontradas: {missing}")

    def create_target(self, name: str, host: str) -> str:
        """Cria um target."""
        with self._get_gmp() as gmp:
            response = gmp.create_target(
                name=name,
                hosts=[host],
                port_list_id=self._cache["port_list_id"]
            )
            target_id = response.get("id")
            if not target_id:
                raise RuntimeError(f"Falha ao criar target: {response.get('status_text')}")
            return target_id

    def create_task(self, name: str, target_id: str) -> str:
        """Cria uma task."""
        with self._get_gmp() as gmp:
            response = gmp.create_task(
                name=name,
                config_id=self._cache["scan_config_id"],
                target_id=target_id,
                scanner_id=self._cache["scanner_id"]
            )
            task_id = response.get("id")
            if not task_id:
                raise RuntimeError(f"Falha ao criar task: {response.get('status_text')}")
            return task_id

    def start_task(self, task_id: str) -> Optional[str]:
        """Inicia uma task."""
        with self._get_gmp() as gmp:
            response = gmp.start_task(task_id)
            report_id = response.find("report_id")
            return report_id.text if report_id is not None else None

    def get_task_status(self, task_id: str) -> tuple:
        """Retorna status de uma task."""
        with self._get_gmp() as gmp:
            response = gmp.get_task(task_id)
            task = response.find("task")

            status_text = task.find("status").text
            progress_elem = task.find("progress")
            progress = int(progress_elem.text) if progress_elem is not None and progress_elem.text else 0

            status_map = {
                "New": ScanStatus.PENDING,
                "Requested": ScanStatus.PENDING,
                "Queued": ScanStatus.PENDING,
                "Running": ScanStatus.RUNNING,
                "Done": ScanStatus.DONE,
                "Stopped": ScanStatus.STOPPED,
            }
            status = status_map.get(status_text, ScanStatus.FAILED)

            report_id = None
            last_report = task.find("last_report/report")
            if last_report is not None:
                report_id = last_report.get("id")

            return status, progress, report_id

    def wait_for_task(self, task_id: str, ip: str) -> tuple:
        """Aguarda conclusão de uma task."""
        self.logger.info(f"Aguardando conclusão do scan para {ip}...")
        start_time = time.time()
        last_progress = -1

        while True:
            try:
                status, progress, report_id = self.get_task_status(task_id)

                if progress != last_progress:
                    elapsed = int(time.time() - start_time)
                    elapsed_str = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
                    bar = self._progress_bar(progress)
                    print(f"\r  [{elapsed_str}] {bar} {progress:3d}% - {status.value}    ", end="", flush=True)
                    last_progress = progress

                if status in [ScanStatus.DONE, ScanStatus.FAILED, ScanStatus.STOPPED]:
                    print()
                    return status, report_id

            except Exception as e:
                self.logger.warning(f"Erro ao verificar status: {e}")

            time.sleep(self.config.poll_interval)

    def _progress_bar(self, progress: int, width: int = 30) -> str:
        filled = int(width * progress / 100)
        return f"[{'█' * filled}{'░' * (width - filled)}]"

    def get_report(self, report_id: str, format_name: str) -> Optional[bytes]:
        """Baixa um relatório."""
        format_id = self._cache.get("report_formats", {}).get(format_name.upper())
        if not format_id:
            format_id = self.REPORT_FORMAT_IDS.get(format_name.upper())

        if not format_id:
            return None

        try:
            with self._get_gmp() as gmp:
                filter_term = "apply_overrides=0 levels=hmlgf rows=-1 min_qod=0"
                response = gmp.get_report(
                    report_id=report_id,
                    report_format_id=format_id,
                    ignore_pagination=True,
                    filter_string=filter_term
                )

                report = response.find("report")
                if report is None:
                    return None

                report_elem = report.find(".//report_format")
                if report_elem is not None and report_elem.tail:
                    content = report_elem.tail.strip()
                    try:
                        return b64decode(content)
                    except Exception:
                        return content.encode()

                if format_name.upper() == "XML":
                    from xml.etree import ElementTree as ET
                    return ET.tostring(report, encoding="unicode").encode()

                return None
        except Exception as e:
            self.logger.warning(f"Erro ao baixar relatório {format_name}: {e}")
            return None

    def get_report_summary(self, report_id: str) -> dict:
        """Retorna resumo de vulnerabilidades."""
        try:
            with self._get_gmp() as gmp:
                response = gmp.get_report(report_id=report_id)
                report = response.find("report/report")

                if report is None:
                    return {}

                results = report.findall(".//results/result")
                summary = {"high": 0, "medium": 0, "low": 0, "log": 0, "total": len(results)}

                for result in results:
                    severity_elem = result.find("severity")
                    if severity_elem is not None and severity_elem.text:
                        try:
                            severity = float(severity_elem.text)
                            if severity >= 7.0:
                                summary["high"] += 1
                            elif severity >= 4.0:
                                summary["medium"] += 1
                            elif severity > 0:
                                summary["low"] += 1
                            else:
                                summary["log"] += 1
                        except ValueError:
                            pass

                return summary
        except Exception as e:
            self.logger.warning(f"Erro ao obter resumo: {e}")
            return {}

    def delete_task(self, task_id: str):
        """Deleta uma task."""
        try:
            with self._get_gmp() as gmp:
                gmp.delete_task(task_id, ultimate=True)
        except Exception as e:
            self.logger.warning(f"Erro ao deletar task: {e}")

    def delete_target(self, target_id: str):
        """Deleta um target."""
        try:
            with self._get_gmp() as gmp:
                gmp.delete_target(target_id, ultimate=True)
        except Exception as e:
            self.logger.warning(f"Erro ao deletar target: {e}")


# ============================================================================
# SCANNER PRINCIPAL
# ============================================================================

class OpenVASScanner:
    """Orquestrador principal do scanner."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.client = GVMClient(config, logger)
        self.state = StateManager(config.state_file)
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._shutdown = False

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.logger.warning("\nInterrupção recebida. Finalizando...")
        self._shutdown = True

    def scan_single(self, ip: str) -> ScanResult:
        """Executa scan de um único IP."""
        result = ScanResult(
            ip=ip,
            status="pending",
            start_time=datetime.now().isoformat()
        )

        try:
            # Criar target
            target_name = f"VulnLab-{ip}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            result.target_id = self.client.create_target(target_name, ip)
            self.logger.info(f"Target criado: {result.target_id}")

            # Criar task
            task_name = f"Scan-{ip}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            result.task_id = self.client.create_task(task_name, result.target_id)
            self.logger.info(f"Task criada: {result.task_id}")

            # Iniciar scan
            result.report_id = self.client.start_task(result.task_id)
            result.status = "running"
            self.state.set_scan(result)
            self.logger.info(f"Scan iniciado para {ip}")

            # Aguardar conclusão
            status, report_id = self.client.wait_for_task(result.task_id, ip)

            if status == ScanStatus.DONE:
                result.report_id = report_id or result.report_id
                result.status = "done"

                # Baixar relatórios
                result.reports_downloaded = self._download_reports(ip, result.report_id)

                # Resumo
                result.vulnerabilities = self.client.get_report_summary(result.report_id)

                self.logger.info(
                    f"Scan concluído: {ip} - "
                    f"Alto: {result.vulnerabilities.get('high', 0)}, "
                    f"Médio: {result.vulnerabilities.get('medium', 0)}, "
                    f"Baixo: {result.vulnerabilities.get('low', 0)}"
                )
            else:
                result.status = "failed"
                result.error = f"Status: {status.value}"
                self.logger.error(f"Scan falhou para {ip}: {result.error}")

            # Cleanup
            if self.config.cleanup_after_scan:
                self.client.delete_task(result.task_id)
                self.client.delete_target(result.target_id)

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            self.logger.error(f"Erro no scan de {ip}: {e}")

        finally:
            result.end_time = datetime.now().isoformat()
            self.state.set_scan(result)

        return result

    def _download_reports(self, ip: str, report_id: str) -> List[str]:
        """Baixa relatórios em múltiplos formatos."""
        downloaded = []

        if self.config.service_name:
            base_name = f"openvas_{self.config.service_name}"
            ip_dir = self.output_dir / base_name
        else:
            base_name = f"scan_{ip.replace('.', '_')}"
            ip_dir = self.output_dir / ip.replace('.', '_')

        self.logger.info(f"Salvando relatórios em: {ip_dir}")
        ip_dir.mkdir(exist_ok=True)

        for format_name in self.config.report_formats:
            self.logger.debug(f"Baixando {format_name}...")

            content = self.client.get_report(report_id, format_name)
            if content:
                file_suffix = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_name.lower()}"
                filename = f"{base_name}_{file_suffix}"
                filepath = ip_dir / filename

                try:
                    with open(filepath, "wb") as f:
                        f.write(content)
                    self.logger.info(f"  Salvo: {filepath.name}")
                    downloaded.append(format_name)
                except IOError as e:
                    self.logger.error(f"Erro ao salvar arquivo {filepath}: {e}")
            else:
                self.logger.warning(f"Não foi possível baixar o relatório no formato {format_name}.")

        return downloaded

    def scan_all(self, ips: list) -> dict:
        """Executa scan de todos os IPs."""
        self.state.start_session()

        pending_ips = self.state.get_pending_ips(ips)

        if len(pending_ips) < len(ips):
            completed = len(ips) - len(pending_ips)
            self.logger.info(f"Retomando: {completed}/{len(ips)} já completados")

        if not pending_ips:
            self.logger.info("Todos os IPs já foram escaneados!")
            return self.state.get_summary()

        self.logger.info(f"Iniciando scan de {len(pending_ips)} IPs...")
        self.logger.info(f"Relatórios em: {self.output_dir.absolute()}")

        # Aguardar GVM
        if not self.client.wait_for_gvm():
            return {"error": "GVM não disponível"}

        try:
            for i, ip in enumerate(pending_ips, 1):
                if self._shutdown:
                    self.logger.warning("Shutdown. Parando após IP atual.")
                    break

                self.logger.info(f"\n{'='*60}")
                self.logger.info(f"[{i}/{len(pending_ips)}] Escaneando: {ip}")
                self.logger.info(f"{'='*60}")

                self.scan_single(ip)

                if i < len(pending_ips) and not self._shutdown:
                    time.sleep(5)

        except Exception as e:
            self.logger.error(f"Erro durante scan: {e}")

        return self.state.get_summary()

    def print_summary(self, summary: dict):
        """Imprime resumo."""
        self.logger.info("\n" + "="*60)
        self.logger.info("RESUMO FINAL")
        self.logger.info("="*60)
        self.logger.info(f"Total: {summary.get('total', 0)}")
        self.logger.info(f"  Concluídos: {summary.get('done', 0)}")
        self.logger.info(f"  Falhas:     {summary.get('failed', 0)}")
        self.logger.info(f"  Pendentes:  {summary.get('pending', 0)}")
        self.logger.info(f"\nRelatórios em: {self.output_dir.absolute()}")


# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

def is_valid_ip(ip: str) -> bool:
    """Valida se uma string é um endereço IP válido (IPv4)."""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))


def load_ips_from_file(filepath: str) -> list:
    """Carrega e valida IPs de arquivo."""
    ips = []
    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line and not line.startswith("#"):
                ip = line.split()[0].split("-")[0].strip()
                if ip:
                    if is_valid_ip(ip):
                        ips.append(ip)
                    else:
                        logging.warning(f"IP inválido ignorado na linha {line_num}: {ip}")
    return ips


def get_ips_from_labsh() -> list:
    """Obtém IPs do lab.sh."""
    import subprocess
    try:
        result = subprocess.run(
            ["./lab.sh", "ips"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent
        )
        ips = []
        for line in result.stdout.split("\n"):
            if " - 172." in line:
                parts = line.split(" - ")
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    if ip and is_valid_ip(ip):
                        ips.append(ip)
        return ips
    except Exception as e:
        print(f"Erro ao executar lab.sh: {e}")
        return []


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="OpenVAS Automated Scanner - VulnLab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s -i 172.30.9.1 172.30.7.1    # IPs específicos
  %(prog)s -f targets.txt               # De arquivo
  %(prog)s --auto                       # Todos do VulnLab
  %(prog)s --auto -v                    # Verbose
        """
    )

    ip_source = parser.add_mutually_exclusive_group(required=True)
    ip_source.add_argument("-f", "--file", help="Arquivo com IPs")
    ip_source.add_argument("-i", "--ips", nargs="+", help="IPs")
    ip_source.add_argument("--auto", action="store_true", help="Auto do lab.sh")

    parser.add_argument("-c", "--config", default="config.yaml", help="Config YAML")
    parser.add_argument("-o", "--output", default="./reports", help="Diretório saída")
    parser.add_argument("-u", "--username", default="admin", help="Usuário GVM")
    parser.add_argument("-p", "--password", default="admin", help="Senha GVM")
    parser.add_argument("--host", default="127.0.0.1", help="Host GVM")
    parser.add_argument("--port", type=int, default=9390, help="Porta GVM")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser.add_argument("--cleanup", action="store_true", help="Deletar após scan")
    parser.add_argument("--reset", action="store_true", help="Resetar estado")
    parser.add_argument("--dry-run", action="store_true", help="Apenas listar IPs")
    parser.add_argument('--service-name', help='Nome do serviço para usar nos relatórios')

    args = parser.parse_args()

    logger = setup_logging(args.verbose)

    config = Config.from_file(args.config)
    config.host = args.host
    config.port = args.port
    config.username = args.username
    config.password = args.password
    config.output_dir = args.output
    config.cleanup_after_scan = args.cleanup
    config.service_name = args.service_name

    if args.file:
        ips = load_ips_from_file(args.file)
    elif args.ips:
        ips = [ip for ip in args.ips if is_valid_ip(ip)]
    else:
        logger.info("Obtendo IPs do lab.sh...")
        ips = get_ips_from_labsh()

    if not ips:
        logger.error("Nenhum IP encontrado!")
        sys.exit(1)

    logger.info(f"IPs carregados: {len(ips)}")

    if args.dry_run:
        logger.info("Modo dry-run - IPs que seriam escaneados:")
        for ip in ips:
            print(f"  - {ip}")
        sys.exit(0)

    if args.reset:
        state_file = Path(config.state_file)
        if state_file.exists():
            state_file.unlink()
            logger.info("Estado resetado")

    scanner = OpenVASScanner(config, logger)
    summary = scanner.scan_all(ips)
    scanner.print_summary(summary)


if __name__ == "__main__":
    main()
