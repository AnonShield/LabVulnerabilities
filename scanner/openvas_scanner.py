#!/usr/bin/env python3
# ============================================================================
# OpenVAS Automated Scanner - Módulo Principal
#
# Autor: VulnLab Project
#
# Este script contém a lógica para se conectar à API do GVM, gerenciar
# tarefas de scan e baixar os relatórios de forma automatizada.
# ============================================================================

# --- Imports ---
import argparse
import json
import logging
import signal
import sys
import time
from base64 import b64decode
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

# --- Classes de Configuração e Modelo de Dados ---

class ScanStatus(Enum):
    """Enumeração para os possíveis status de um scan."""
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    STOPPED = "stopped"

@dataclass
class Config:
    """
    Mantém a configuração do scanner, carregada de um arquivo YAML e
    potencialmente sobrescrita por argumentos da linha de comando.
    """
    # Conexão GVM
    host: str = "127.0.0.1"
    port: int = 9390
    username: str = "admin"
    password: str = "admin"

    # Nomes de configuração do GVM
    scan_config_name: str = "Full and fast"
    port_list_name: str = "All TCP and Nmap top 100 UDP"
    scanner_name: str = "OpenVAS Default"

    # Comportamento do Script
    report_formats: List[str] = field(default_factory=lambda: ["PDF", "XML", "CSV", "TXT"])
    output_dir: str = "./reports"
    state_file: str = "./scanner_state.json"
    cleanup_after_scan: bool = False
    retry_attempts: int = 3
    retry_delay: int = 10
    poll_interval: int = 30
    connection_timeout: int = 120
    service_name: Optional[str] = None  # Injetado pelo orquestrador

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Carrega a configuração de um arquivo YAML, usando os padrões da classe se o arquivo não existir."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            # Retorna uma nova instância, atualizada apenas com as chaves válidas do YAML
            return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
        except (FileNotFoundError, ImportError):
            # Se o arquivo ou a lib yaml não existem, retorna a configuração padrão
            return cls()

@dataclass
class ScanResult:
    """Modelo de dados para o resultado de um scan, usado para o gerenciamento de estado."""
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


# --- Classes de Gerenciamento ---

class StateManager:
    """
    Gerencia o estado da sessão de scan (scanner_state.json), permitindo
    que o processo seja interrompido e retomado sem perder o progresso.
    """
    def __init__(self, state_file_path: str):
        self.state_file = Path(state_file_path)
        self.state: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        """Carrega o estado do arquivo JSON, retornando um estado vazio em caso de erro."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                logging.warning("Arquivo de estado corrompido ou ilegível. Começando do zero.")
        return {"scans": {}, "session_start": None}

    def save(self):
        """Salva o estado atual no arquivo JSON."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump(self.state, f, indent=2, default=str)
        except IOError as e:
            logging.error(f"Não foi possível salvar o arquivo de estado: {e}")

    def set_scan(self, result: ScanResult):
        """Atualiza o estado de um scan específico."""
        self.state.setdefault("scans", {})[result.ip] = result.__dict__
        self.save()

    def is_completed(self, ip: str) -> bool:
        """Verifica se um scan para um dado IP foi concluído com sucesso."""
        scans = self.state.get("scans", {})
        scan_data = scans.get(ip)
        return scan_data and scan_data.get("status") == "done" and bool(scan_data.get("reports_downloaded"))

    def get_pending_ips(self, all_ips: List[str]) -> List[str]:
        """Filtra a lista de IPs, retornando apenas os que não foram concluídos."""
        return [ip for ip in all_ips if not self.is_completed(ip)]

class GVMClient:
    """
    Encapsula toda a comunicação com a API do GVM (GMP), abstraindo a
    complexidade do protocolo para as operações necessárias ao scanner.
    """
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.transform = EtreeTransform()
        self._cache: Dict[str, Any] = {}

    @contextmanager
    def _get_gmp(self) -> Gmp:
        """Context manager para uma conexão GMP autenticada e resiliente."""
        connection = TLSConnection(hostname=self.config.host, port=self.config.port, timeout=self.config.connection_timeout)
        with Gmp(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.config.username, self.config.password)
            yield gmp

    def wait_for_gvm(self) -> bool:
        """Aguarda o serviço GVM ficar disponível, com um timeout."""
        # Código de espera omitido para brevidade, mas funcionaria como antes
        self.logger.info(f"Conectando ao GVM em {self.config.host}:{self.config.port}...")
        try:
            with self._get_gmp() as gmp:
                version_resp = gmp.get_version()
                self.logger.info(f"GVM disponível! Versão GMP: {version_resp.find('version').text}")
                self._cache_ids(gmp)
                return True
        except Exception as e:
            self.logger.error(f"Falha ao conectar com o GVM: {e}")
            return False

    def _cache_ids(self, gmp: Gmp):
        """Carrega UUIDs de configuração do GVM para evitar chamadas repetidas."""
        self.logger.debug("Carregando e fazendo cache dos UUIDs de configuração...")
        # Lógica de cache omitida para brevidade
        self._cache["scan_config_id"] = "daba56c8-73ec-11df-a475-002264764cea" # Full and fast
        self._cache["port_list_id"] = "730ef368-57e2-11e1-a90f-406186ea4fc5" # All TCP and Nmap top 100 UDP
        self._cache["scanner_id"] = "08b69003-5fc2-4037-a479-93b440211c73" # OpenVAS Default

    def get_report(self, report_id: str, format_id: str) -> Optional[bytes]:
        """Baixa um relatório completo, usando um filtro temporário para garantir que todos os dados sejam incluídos."""
        try:
            with self._get_gmp() as gmp:
                filter_term = "apply_overrides=0 levels=chmlgf rows=-1 min_qod=0 notes=1 overrides=1"
                filter_id_resp = gmp.create_filter(name=f"Temp-Full-Report-{time.time()}", term=filter_term)
                filter_id = filter_id_resp.get("id")
                if not filter_id:
                    raise RuntimeError("Falha ao criar filtro temporário.")
                
                try:
                    response = gmp.get_report(report_id=report_id, report_format_id=format_id, ignore_pagination=True, filter_id=filter_id)
                    report = response.find("report")
                    report_elem = report.find(".//report_format") if report is not None else None
                    if report_elem is not None and report_elem.tail:
                        return b64decode(report_elem.tail.strip())
                finally:
                    gmp.delete_filter(filter_id) # Garante a limpeza
        except Exception as e:
            self.logger.error(f"Falha ao baixar relatório: {e}")
        return None
    # Outros métodos do GVMClient (create_target, create_task, etc.) seriam igualmente refinados
    # ...


class OpenVASScanner:
    """Orquestrador principal que combina configuração, estado e cliente GVM para executar os scans."""
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.client = GVMClient(config, logger)
        self.state = StateManager(config.state_file)
        self.output_dir = Path(config.output_dir)
        # ... o resto da inicialização ...

    def scan_single(self, ip: str) -> ScanResult:
        """Executa o fluxo completo de scan para um único IP."""
        # Lógica de scan omitida para brevidade, mas seria a mesma
        # ...
        pass

    def _download_reports(self, ip: str, report_id: str) -> List[str]:
        """Baixa os relatórios nos formatos configurados, usando a nomenclatura correta."""
        # Lógica de download omitida para brevidade, mas seria a mesma
        # ...
        pass

    # ... o resto dos métodos ...

# --- Função Principal e CLI ---

def main():
    """Ponto de entrada principal, parsing de argumentos e inicialização."""
    # Lógica do parser omitida para brevidade
    # ...
    pass


if __name__ == "__main__":
    # Esta verificação garante que o código dentro do `main()` só rode
    # quando o script é executado diretamente.
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperação interrompida pelo usuário.")
        sys.exit(1)