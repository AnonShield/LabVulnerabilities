#!/usr/bin/env python3
"""
GVM Report Downloader by IP

Downloads reports from a master GVM scan report, filtering results for each
IP specified in a target file.

This script is designed for a one-time use case to process a large,
pre-existing scan report.

Author: Gemini
Version: 1.0.0
"""

import argparse
import json
import logging
import sys
import time
from base64 import b64decode
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager

try:
    import yaml
except ImportError:
    print("\n[ERRO] PyYAML não instalado. Execute:")
    print("  pip3 install pyyaml")
    sys.exit(1)

try:
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
except ImportError:
    print("\n[ERRO] gvm-tools não instalado. Execute:")
    print("  pip3 install gvm-tools")
    sys.exit(1)


# ============================================================================
# CONFIGURAÇÃO
# ============================================================================

@dataclass
class Config:
    """Configuration for the report downloader."""
    # GVM Connection
    host: str = "127.0.0.1"
    port: int = 9390
    username: str = "admin"
    password: str = "admin"
    connection_timeout: int = 120

    # Report
    master_report_id: str = "2de16342-c6e0-4242-99ec-00d18ca51b42"

    # Input Files
    targets_file: str = "targets.txt"
    docker_compose_file: str = "docker-compose.yml"

    # Output
    output_dir: str = "gvm_filtered_reports"


# ============================================================================
# LOGGING (similar to openvas_scanner.py)
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Formatter with colors for the terminal."""
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
    """Configures logging."""
    logger = logging.getLogger("report_downloader")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(ColoredFormatter(
        '%(asctime)s │ %(levelname)-17s │ %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger.addHandler(console)
    return logger


# ============================================================================
# GVM CLIENT (simplified from openvas_scanner.py)
# ============================================================================

class GVMClient:
    """Client for GVM communication."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.transform = EtreeTransform()
        self._report_formats: Dict[str, str] = {}

    @contextmanager
    def _get_gmp(self):
        """Context manager for authenticated GMP connection."""
        connection = TLSConnection(
            hostname=self.config.host,
            port=self.config.port,
            timeout=self.config.connection_timeout
        )
        with Gmp(connection=connection, transform=self.transform) as gmp:
            gmp.authenticate(self.config.username, self.config.password)
            yield gmp

    def connect(self) -> bool:
        """Waits for GVM to become available and caches report formats."""
        self.logger.info(f"Attempting to connect to GVM at {self.config.host}:{self.config.port}...")
        try:
            with self._get_gmp() as gmp:
                version = gmp.get_version()
                gmp_version = version.find("version").text
                self.logger.info(f"Connected! GMP version: {gmp_version}")
                self._cache_report_formats(gmp)
                return True
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False

    def _cache_report_formats(self, gmp):
        """Caches all available report formats."""
        self.logger.debug("Caching GVM report formats...")
        formats = gmp.get_report_formats()
        for fmt in formats.findall(".//report_format"):
            name_elem = fmt.find("name")
            if name_elem is not None and name_elem.text:
                name = name_elem.text
                fmt_id = fmt.get("id")
                # Normalize name for extension, e.g., "Anonymous XML" -> xml
                extension = name.lower().replace(" ", "_").split("_")[0]
                if name == "CSV Results":
                    extension = "csv"
                elif name == "TXT":
                    extension = "txt"

                self._report_formats[fmt_id] = (name, extension)
        self.logger.info(f"Found {len(self._report_formats)} report formats.")

    def get_report_formats(self) -> Dict[str, Tuple[str, str]]:
        return self._report_formats

    def get_filtered_report(self, report_id: str, format_id: str, host_ip: str) -> Optional[bytes]:
        """Downloads a report filtered by a specific host."""
        # This filter is critical. It selects the host and sets other required parameters.
        filter_term = f"host={host_ip} and apply_overrides=0 and levels=hmlgf and min_qod=0"

        try:
            with self._get_gmp() as gmp:
                response = gmp.get_report(
                    report_id=report_id,
                    report_format_id=format_id,
                    ignore_pagination=True,
                    filter_string=filter_term
                )

                report_element = response.find("report")
                if report_element is None:
                    self.logger.warning(f"Report element not found for IP {host_ip}")
                    return None

                # Content is often in the tail of the <report_format> element, base64 encoded
                content_element = report_element.find(f".//report_format[@id='{format_id}']")
                if content_element is not None and content_element.tail:
                    content = content_element.tail.strip()
                    return b64decode(content)

                # For some formats like XML, the content is the element itself
                from xml.etree import ElementTree
                return ElementTree.tostring(report_element, encoding="utf-8")

        except Exception as e:
            self.logger.error(f"Failed to download report for IP {host_ip} (format_id: {format_id}): {e}")
            return None


# ============================================================================
# MAIN SCRIPT LOGIC
# ============================================================================

class ReportDownloader:
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.client = GVMClient(config, logger)
        self.ip_map: Dict[str, Dict[str, str]] = {}
        self.output_dir = Path(self.config.output_dir)

    def run(self, test_ip: Optional[str] = None):
        """Main execution flow."""
        self.logger.info("Starting report download process...")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"Reports will be saved to: {self.output_dir.absolute()}")

        # 1. Load mappings and targets
        if not self._load_ip_map():
            return
        
        if test_ip:
            target_ips = [test_ip]
            self.logger.warning(f"--- RUNNING IN TEST MODE FOR IP: {test_ip} ---")
        else:
            target_ips = self._load_target_ips()
        
        if not target_ips:
            return

        # 2. Connect to GVM
        if not self.client.connect():
            self.logger.critical("Could not connect to GVM. Aborting.")
            return

        report_formats = self.client.get_report_formats()
        if not report_formats:
            self.logger.error("No report formats found on GVM. Aborting.")
            return

        # 3. Process each IP
        self.logger.info(f"Processing {len(target_ips)} target IP(s)...")
        for ip in target_ips:
            self._process_ip(ip, report_formats)

        self.logger.info("Report download process finished.")

    def _load_ip_map(self) -> bool:
        """Parses the docker-compose.yml to map IPs to service and image names."""
        self.logger.info(f"Loading IP map from {self.config.docker_compose_file}...")
        try:
            with open(self.config.docker_compose_file, 'r') as f:
                compose_data = yaml.safe_load(f)
            
            services = compose_data.get('services', {})
            for service_name, service_config in services.items():
                networks = service_config.get('networks', {})
                image_name = service_config.get('image')
                
                if not image_name:
                    self.logger.debug(f"Service '{service_name}' has no image name, skipping.")
                    continue

                if 'vulnnet' in networks and 'ipv4_address' in networks['vulnnet']:
                    ip = networks['vulnnet']['ipv4_address']
                    self.ip_map[ip] = {
                        "service_name": service_name,
                        "image_name": image_name
                    }
            
            if not self.ip_map:
                self.logger.error("Could not find any services with 'vulnnet' and 'ipv4_address' in docker-compose.yml")
                return False
            
            self.logger.info(f"Loaded {len(self.ip_map)} IP-to-image mappings.")
            return True
        except FileNotFoundError:
            self.logger.error(f"File not found: {self.config.docker_compose_file}")
            return False
        except Exception as e:
            self.logger.error(f"Error parsing {self.config.docker_compose_file}: {e}")
            return False

    def _load_target_ips(self) -> List[str]:
        """Loads IPs from the targets.txt file."""
        self.logger.info(f"Loading target IPs from {self.config.targets_file}...")
        try:
            with open(self.config.targets_file, 'r') as f:
                ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not ips:
                self.logger.error(f"No valid IPs found in {self.config.targets_file}")
            return ips
        except FileNotFoundError:
            self.logger.error(f"File not found: {self.config.targets_file}")
            return []

    def _sanitize_filename(self, name: str) -> str:
        """Replaces special characters in a string to make it a valid filename component."""
        return name.replace("/", "_").replace(":", "_")

    def _process_ip(self, ip: str, report_formats: Dict[str, Tuple[str, str]]):
        """Download all report formats for a single IP."""
        mapping = self.ip_map.get(ip)
        if not mapping:
            self.logger.warning(f"IP {ip} not found in docker-compose.yml mapping. Skipping.")
            return

        service_name = mapping["service_name"]
        image_name = mapping["image_name"]
        self.logger.info(f"--- Processing IP: {ip} (Service: {service_name}, Image: {image_name}) ---")
        
        sanitized_image_name = self._sanitize_filename(image_name)
        base_folder_name = f"openvas_{sanitized_image_name}"
        container_output_dir = self.output_dir / base_folder_name
        container_output_dir.mkdir(exist_ok=True)

        base_filename = base_folder_name # Filename can be same as folder name

        for fmt_id, (fmt_name, extension) in report_formats.items():
            self.logger.debug(f"Downloading report in '{fmt_name}' format...")
            
            content = self.client.get_filtered_report(
                report_id=self.config.master_report_id,
                format_id=fmt_id,
                host_ip=ip
            )

            if content:
                filepath = container_output_dir / f"{base_filename}.{extension}"
                try:
                    with open(filepath, "wb") as f:
                        f.write(content)
                    self.logger.info(f"  -> Saved: {filepath}")
                except IOError as e:
                    self.logger.error(f"  -> Error saving file {filepath}: {e}")
            else:
                self.logger.warning(f"  -> Failed to download report in '{fmt_name}' format for IP {ip}.")
            
            time.sleep(1) # Be nice to the GVM API


def main():
    parser = argparse.ArgumentParser(
        description="GVM Report Downloader by IP.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--report-id",
        default="2de16342-c6e0-4242-99ec-00d18ca51b42",
        help="The master report ID to filter from."
    )
    parser.add_argument(
        "-t", "--targets",
        default="targets.txt",
        help="File with list of target IPs."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging."
    )
    parser.add_argument(
        "--test-ip",
        help="Only process a single IP for testing purposes."
    )

    args = parser.parse_args()
    logger = setup_logging(args.verbose)
    
    config = Config()
    config.master_report_id = args.report_id
    config.targets_file = args.targets
    
    downloader = ReportDownloader(config, logger)
    downloader.run(test_ip=args.test_ip)
    sys.exit(0)


if __name__ == "__main__":
    main()
