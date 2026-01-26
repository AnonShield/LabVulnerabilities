# OpenVAS Automated Scanner

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GVM](https://img.shields.io/badge/GVM-22.x-green.svg)](https://greenbone.github.io/docs/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-grade, enterprise-ready vulnerability scanning automation framework for OpenVAS/GVM integration with the VulnLab environment. Designed with maintainability, extensibility, and resilience as core principles.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Design Patterns & Principles](#design-patterns--principles)
3. [Component Reference](#component-reference)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage Guide](#usage-guide)
7. [Scan Modes](#scan-modes)
8. [State Management & Resumability](#state-management--resumability)
9. [Report Formats & Structure](#report-formats--structure)
10. [API Reference](#api-reference)
11. [Troubleshooting](#troubleshooting)
12. [Security Considerations](#security-considerations)
13. [Extensibility Guide](#extensibility-guide)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VulnLab Scanner Architecture                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────┐   │
│  │  CLI Layer   │───▶│ Orchestrator │───▶│     OpenVAS Scanner Core     │   │
│  │  (run.sh)    │    │(scan_manager)│    │    (openvas_scanner.py)      │   │
│  └──────────────┘    └──────────────┘    └──────────────────────────────┘   │
│                                                        │                     │
│                                                        ▼                     │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        Strategy Layer                                 │   │
│  │  ┌────────────────┐ ┌────────────────┐ ┌────────────────────────┐    │   │
│  │  │  Sequential    │ │     Batch      │ │   Parallel Tasks       │    │   │
│  │  │  Strategy      │ │   Strategy     │ │     Strategy           │    │   │
│  │  │ (1 IP/task)    │ │ (N IPs/task)   │ │ (N concurrent tasks)   │    │   │
│  │  └────────────────┘ └────────────────┘ └────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                          │                                   │
│                                          ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         GVM Client Layer                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │   Target    │  │    Task     │  │   Report    │  │   Cache     │  │   │
│  │  │  Manager    │  │  Manager    │  │  Downloader │  │  Manager    │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                          │                                   │
│                                          ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      Persistence Layer                                │   │
│  │  ┌─────────────────────┐          ┌─────────────────────────────┐    │   │
│  │  │    StateManager     │          │      Report Storage         │    │   │
│  │  │ (scanner_state.json)│          │    (reports/<ip>/*.pdf)     │    │   │
│  │  └─────────────────────┘          └─────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                          │                                   │
│                                          ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    External Services                                  │   │
│  │  ┌─────────────────────────────┐    ┌─────────────────────────────┐  │   │
│  │  │   Greenbone Vulnerability   │    │      Docker Network         │  │   │
│  │  │   Manager (GVM/OpenVAS)     │    │       (vulnnet)             │  │   │
│  │  │   Port: 9390 (GMP API)      │    │    172.30.0.0/16            │  │   │
│  │  └─────────────────────────────┘    └─────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Input**: IPs from CLI arguments, file, or auto-discovery via `lab.sh ips`
2. **Filtering**: StateManager excludes already-completed scans (resumability)
3. **Strategy Selection**: Based on `--mode` flag, appropriate scan strategy is instantiated
4. **Execution**: Strategy orchestrates target/task creation via GVMClient
5. **Monitoring**: Polling loop tracks progress with configurable intervals
6. **Collection**: Reports downloaded in multiple formats (PDF, XML, CSV, TXT)
7. **Persistence**: Results and metadata persisted to JSON state file

---

## Design Patterns & Principles

### Strategy Pattern (Gang of Four)

The scanner implements the **Strategy Pattern** to support multiple scan execution modes without modifying the core scanner logic. This allows runtime selection of scan behavior.

```python
class ScanStrategy(ABC):
    @abstractmethod
    def scan(self, scanner: 'OpenVASScanner', ips: List[str]) -> Dict[str, 'ScanResult']:
        pass

# Concrete Strategies
class SequentialStrategy(ScanStrategy): ...   # One IP at a time
class BatchStrategy(ScanStrategy): ...        # Multiple IPs per GVM target
class ParallelTasksStrategy(ScanStrategy): ... # Concurrent GVM tasks
```

**Benefits:**
- Open/Closed Principle: Add new strategies without modifying existing code
- Single Responsibility: Each strategy handles one execution mode
- Testability: Strategies can be unit-tested in isolation

### Factory Pattern

The `get_scan_strategy()` factory function encapsulates strategy instantiation:

```python
def get_scan_strategy(mode: str, config: Config) -> ScanStrategy:
    if mode == "batch":
        return BatchStrategy(batch_size=config.batch_size)
    elif mode == "parallel":
        return ParallelTasksStrategy(max_concurrent=config.max_concurrent)
    return SequentialStrategy()
```

### Context Manager Pattern

All GVM connections use Python's context manager protocol for guaranteed resource cleanup:

```python
@contextmanager
def _get_gmp(self):
    connection = TLSConnection(hostname=self.config.host, port=self.config.port)
    with Gmp(connection=connection, transform=self.transform) as gmp:
        gmp.authenticate(self.config.username, self.config.password)
        yield gmp
    # Connection automatically closed on exit
```

### Data Classes for Immutable Configuration

Configuration and results use `@dataclass` for type safety and immutability:

```python
@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 9390
    # ... with factory methods for loading from YAML
```

### SOLID Principles Applied

| Principle | Implementation |
|-----------|----------------|
| **S**ingle Responsibility | Each class has one job: `GVMClient` handles API, `StateManager` handles persistence |
| **O**pen/Closed | Strategy pattern allows extension without modification |
| **L**iskov Substitution | All strategies are interchangeable via base class interface |
| **I**nterface Segregation | `ScanStrategy` defines minimal required interface |
| **D**ependency Inversion | Scanner depends on abstract `ScanStrategy`, not concrete implementations |

---

## Component Reference

### File Structure

```
scanner/
├── openvas_scanner.py      # Core scanner implementation (1300+ LOC)
├── config.yaml             # YAML configuration file
├── requirements.txt        # Python dependencies
├── scanner_state.json      # Persistent state (auto-generated)
├── bin/
│   ├── setup.sh           # Environment setup script
│   ├── run.sh             # CLI wrapper with preset commands
│   └── scan_manager.sh    # Container lifecycle orchestrator
├── logs/                   # Timestamped log files (auto-generated)
│   └── scanner_YYYYMMDD_HHMMSS.log
├── reports/                # Scan reports organized by IP (auto-generated)
│   ├── 172_30_9_1/
│   │   ├── scan_172_30_9_1_20260125_001530.pdf
│   │   ├── scan_172_30_9_1_20260125_001530.xml
│   │   └── ...
│   └── batches/           # Batch mode reports
│       └── batch_1_172-30-9/
└── venv/                   # Python virtual environment (auto-generated)
```

### Core Classes

| Class | Responsibility | Key Methods |
|-------|---------------|-------------|
| `Config` | Configuration management with YAML loading | `from_file()` |
| `ScanStatus` | Enum for scan lifecycle states | `PENDING`, `RUNNING`, `DONE`, `FAILED`, `STOPPED` |
| `ScanResult` | Data class for individual scan results | Contains IP, status, timestamps, vulnerability counts |
| `StateManager` | JSON-based persistence for resumability | `get_scan()`, `set_scan()`, `is_completed()`, `get_pending_ips()` |
| `GVMClient` | GMP API wrapper with connection pooling | `create_target()`, `create_task()`, `start_task()`, `wait_for_task()`, `get_report()` |
| `OpenVASScanner` | Main orchestrator with signal handling | `scan_single()`, `scan_all()`, `print_summary()` |

### Shell Scripts

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `setup.sh` | Creates venv, installs dependencies, validates OpenVAS | First-time setup |
| `run.sh` | CLI wrapper with preset scan profiles | Daily operations |
| `scan_manager.sh` | Full orchestration: start container → scan → stop | Resource-constrained environments |

---

## Installation

### Prerequisites

- **Docker** and **Docker Compose** v1.29+
- **Python** 3.8+ with `venv` module
- **jq** (for shell scripts)
- **OpenVAS/GVM** container running on the network

### Quick Start

```bash
# 1. Navigate to scanner directory
cd scanner/

# 2. Run setup script
./bin/setup.sh

# 3. Verify OpenVAS is running
docker ps | grep openvas

# 4. Test connectivity
./bin/run.sh status
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
mkdir -p reports logs
```

### OpenVAS Container Setup

If OpenVAS is not running, start it with GMP API exposed:

```bash
docker run -d \
  --name openvas \
  -p 9392:9392 \
  -p 9390:9390 \
  -e PASSWORD="admin" \
  --network trabalho_vulnnet \
  immauss/openvas
```

**Important:** Port 9390 must be exposed for the GMP API connection.

---

## Configuration

### config.yaml Reference

```yaml
# ═══════════════════════════════════════════════════════════════════════════
# GVM CONNECTION
# ═══════════════════════════════════════════════════════════════════════════
host: "127.0.0.1"           # GVM host (use container IP if on Docker network)
port: 9390                  # GMP API port (NOT the web UI port 9392)
username: "admin"           # GVM username
password: "admin"           # GVM password

# ═══════════════════════════════════════════════════════════════════════════
# SCAN CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
scan_config_name: "Full and fast"
# Options:
#   - "Full and fast"           → Recommended, ~30-60min/host
#   - "Full and fast ultimate"  → More thorough
#   - "Full and deep"           → Comprehensive, ~2-4h/host
#   - "Full and deep ultimate"  → Maximum coverage
#   - "Discovery"               → Port scan only, fast

port_list_name: "All TCP and Nmap top 100 UDP"
# Options:
#   - "All TCP and Nmap top 100 UDP"    → Recommended
#   - "All TCP"                         → TCP only
#   - "All IANA assigned TCP and UDP"   → Most comprehensive
#   - "Nmap top 1000 TCP and top 100 UDP"

scanner_name: "OpenVAS Default"

# ═══════════════════════════════════════════════════════════════════════════
# REPORT FORMATS
# ═══════════════════════════════════════════════════════════════════════════
report_formats:
  - "PDF"    # Human-readable report
  - "XML"    # Machine-parseable, full data
  - "CSV"    # Spreadsheet import
  - "TXT"    # Plain text summary

# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT & STATE
# ═══════════════════════════════════════════════════════════════════════════
output_dir: "./reports"
state_file: "./scanner_state.json"

# ═══════════════════════════════════════════════════════════════════════════
# BEHAVIOR
# ═══════════════════════════════════════════════════════════════════════════
cleanup_after_scan: false   # Delete GVM task/target after scan completes
retry_attempts: 3           # Connection retry count
retry_delay: 10             # Seconds between retries
poll_interval: 30           # Seconds between status checks
connection_timeout: 120     # GMP connection timeout

# ═══════════════════════════════════════════════════════════════════════════
# PARALLELISM
# ═══════════════════════════════════════════════════════════════════════════
parallel:
  mode: "sequential"        # sequential | batch | parallel
  max_concurrent: 4         # Parallel mode: concurrent tasks
  batch_size: 10            # Batch mode: IPs per target
```

### Environment Variable Overrides

CLI arguments take precedence over config file. Environment variables can be used for sensitive data:

```bash
export GVM_HOST="192.168.1.100"
export GVM_USERNAME="scanner"
export GVM_PASSWORD="secure_password"
```

---

## Usage Guide

### Quick Reference

```bash
# Single IP scan
./bin/run.sh single 172.30.9.1

# Multiple IPs (sequential)
python3 openvas_scanner.py -i 172.30.9.1 172.30.7.1 172.30.8.1

# From file
python3 openvas_scanner.py -f targets.txt

# Auto-discover from VulnLab
python3 openvas_scanner.py --auto

# With verbose logging
python3 openvas_scanner.py -i 172.30.9.1 -v

# Dry run (list targets without scanning)
python3 openvas_scanner.py --auto --dry-run
```

### Preset Profiles (via run.sh)

```bash
./bin/run.sh all          # All VulnLab containers
./bin/run.sh webapps      # Web applications only
./bin/run.sh databases    # Database servers only
./bin/run.sh cves         # CVE-specific containers
./bin/run.sh custom       # IPs from targets.txt
```

### Orchestrated Scanning (Resource-Efficient)

For machines with limited RAM, use the orchestrator which starts/stops containers one at a time:

```bash
./bin/scan_manager.sh
```

This script:
1. Reads all services from `docker-compose.yml`
2. For each service: start → wait → get IP → scan → stop
3. Maintains state for resumability
4. Handles interrupts gracefully

---

## Scan Modes

### Sequential Mode (Default)

Scans one IP at a time. Best for reliability and debugging.

```bash
python3 openvas_scanner.py -i 172.30.9.1 172.30.7.1 --mode sequential
```

**Characteristics:**
- One GVM task active at a time
- Individual reports per IP
- Progress visible in real-time
- Lowest resource usage

### Batch Mode

Groups multiple IPs into a single GVM target/task. GVM scans them internally in parallel.

```bash
python3 openvas_scanner.py -i 172.30.9.1 172.30.7.1 172.30.8.1 \
  --mode batch --batch-size 5
```

**Characteristics:**
- One consolidated report per batch
- GVM optimizes internal parallelism
- Faster for many similar targets
- Cannot track individual IP progress

**Use Case:** Scanning a subnet of similar services.

### Parallel Mode

Runs multiple GVM tasks concurrently with centralized monitoring.

```bash
python3 openvas_scanner.py -i 172.30.9.1 172.30.7.1 172.30.8.1 172.30.6.1 \
  --mode parallel --max-concurrent 2
```

**Characteristics:**
- Individual reports per IP
- Real-time progress panel showing all active scans
- Configurable concurrency limit
- Higher resource usage

**Use Case:** Fast scanning when GVM has sufficient resources.

### Mode Comparison

| Feature | Sequential | Batch | Parallel |
|---------|------------|-------|----------|
| Reports | Per IP | Per Batch | Per IP |
| Progress | Per IP | Per Batch | All IPs |
| Speed | Slowest | Fast | Fastest |
| Resources | Low | Medium | High |
| Resumability | Per IP | Per Batch | Per IP |

---

## State Management & Resumability

### State File Structure

The scanner maintains persistent state in `scanner_state.json`:

```json
{
  "session_start": "2026-01-25T10:30:00.000000",
  "scans": {
    "172.30.9.1": {
      "ip": "172.30.9.1",
      "status": "done",
      "task_id": "a1b2c3d4-...",
      "target_id": "e5f6g7h8-...",
      "report_id": "i9j0k1l2-...",
      "start_time": "2026-01-25T10:30:15.123456",
      "end_time": "2026-01-25T11:15:42.654321",
      "reports_downloaded": ["PDF", "XML", "CSV", "TXT"],
      "error": null,
      "vulnerabilities": {
        "high": 5,
        "medium": 12,
        "low": 23,
        "log": 45,
        "total": 85
      }
    }
  }
}
```

### Resumability

The scanner automatically skips completed scans:

```bash
# First run - scans all 10 IPs
python3 openvas_scanner.py -i IP1 IP2 ... IP10

# Interrupted after IP5
# ^C

# Resume - automatically skips IP1-IP5, continues with IP6-IP10
python3 openvas_scanner.py -i IP1 IP2 ... IP10
```

### Force Re-scan

To re-scan already completed IPs:

```bash
python3 openvas_scanner.py -i 172.30.9.1 --force
```

### Reset State

To start fresh:

```bash
./bin/run.sh reset
# or
rm scanner_state.json
```

---

## Report Formats & Structure

### Available Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| PDF | `.pdf` | Executive summaries, human review |
| XML | `.xml` | Integration with other tools, full data |
| CSV | `.csv` | Spreadsheet analysis, data import |
| TXT | `.txt` | Quick text-based review |
| HTML | `.html` | Web-based viewing (optional) |

### Directory Structure

```
reports/
├── 172_30_9_1/                              # IP-based directory
│   ├── scan_172_30_9_1_20260125_103015.pdf  # Timestamped reports
│   ├── scan_172_30_9_1_20260125_103015.xml
│   ├── scan_172_30_9_1_20260125_103015.csv
│   └── scan_172_30_9_1_20260125_103015.txt
├── openvas_dvwa/                            # Service-named (with --service-name)
│   ├── openvas_dvwa_20260125_110000.pdf
│   └── ...
└── batches/                                 # Batch mode reports
    └── batch1_172-30-9/
        └── batch_batch1_172-30-9_20260125_120000.pdf
```

### Custom Service Naming

Use `--service-name` for human-readable report directories:

```bash
python3 openvas_scanner.py -i 172.30.9.1 --service-name dvwa
# Reports saved to: reports/openvas_dvwa/
```

---

## API Reference

### CLI Arguments

```
usage: openvas_scanner.py [-h] (-f FILE | -i IPS [IPS ...] | --auto)
                          [-c CONFIG] [-o OUTPUT] [-u USERNAME] [-p PASSWORD]
                          [--host HOST] [--port PORT] [-v] [--cleanup]
                          [--reset] [--force] [--dry-run]
                          [--service-name NAME]
                          [--mode {sequential,batch,parallel}]
                          [--max-concurrent N] [--batch-size N]

Arguments:
  -f, --file FILE          Load IPs from file (one per line)
  -i, --ips IPS [IPS ...]  Specify IPs directly
  --auto                   Auto-discover IPs from lab.sh

  -c, --config FILE        Path to config.yaml (default: config.yaml)
  -o, --output DIR         Reports output directory (default: ./reports)
  -u, --username USER      GVM username (default: admin)
  -p, --password PASS      GVM password (default: admin)
  --host HOST              GVM host (default: 127.0.0.1)
  --port PORT              GVM port (default: 9390)

  -v, --verbose            Enable debug logging
  --cleanup                Delete GVM tasks/targets after scan
  --reset                  Clear state file before scanning
  --force                  Re-scan already completed IPs
  --dry-run                List IPs without scanning

  --service-name NAME      Custom name for report directory
  --mode MODE              Scan mode: sequential, batch, parallel
  --max-concurrent N       Max concurrent tasks (parallel mode)
  --batch-size N           IPs per batch (batch mode)
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (missing deps, invalid config) |
| 130 | Interrupted by user (SIGINT) |

---

## Troubleshooting

### Connection Issues

**Error:** `Connection refused to 127.0.0.1:9390`

```bash
# Verify OpenVAS is running
docker ps | grep openvas

# Check port exposure
docker port openvas 9390

# If not exposed, recreate container with -p 9390:9390
```

**Error:** `Authentication failed`

```bash
# Verify credentials in config.yaml match GVM setup
# Default: admin/admin

# Check GVM logs
docker logs openvas 2>&1 | tail -50
```

### Scan Failures

**Error:** `Scan config not found`

```bash
# GVM may still be initializing. Wait and retry.
# Check GVM readiness:
docker exec openvas gvm-cli socket --protocol GMP --xml "<get_version/>"
```

**Error:** `Target creation failed`

```bash
# IP may be unreachable. Verify network:
docker exec openvas ping -c 1 172.30.9.1

# Ensure OpenVAS is on vulnnet:
docker network connect trabalho_vulnnet openvas
```

### Performance Issues

**Slow scans:**
- Use `scan_config_name: "Full and fast"` instead of "Full and deep"
- Reduce `port_list_name` to `"Nmap top 1000 TCP and top 100 UDP"`
- Use batch mode for similar targets

**High memory usage:**
- Use sequential mode
- Use `scan_manager.sh` to scan one container at a time
- Enable `cleanup_after_scan: true`

### Log Analysis

```bash
# View latest log
tail -f logs/scanner_*.log | head -1 | xargs tail -f

# Search for errors
grep -i error logs/scanner_*.log

# View scan summary
grep "RESUMO FINAL" logs/scanner_*.log -A 10
```

---

## Security Considerations

### Credential Management

1. **Never commit credentials** to version control
2. Use environment variables for production:
   ```bash
   export GVM_PASSWORD="$(cat /run/secrets/gvm_password)"
   ```
3. Consider using Docker secrets or HashiCorp Vault

### Network Isolation

1. Scanner should run inside the isolated `vulnnet` network
2. Never expose GVM port 9390 to the public internet
3. Use firewall rules to restrict access

### Report Handling

1. Reports contain sensitive vulnerability data
2. Restrict `reports/` directory permissions: `chmod 700 reports/`
3. Encrypt reports at rest if required by compliance

---

## Extensibility Guide

### Adding a New Scan Strategy

1. Create a new class extending `ScanStrategy`:

```python
class CustomStrategy(ScanStrategy):
    def scan(self, scanner: 'OpenVASScanner', ips: List[str]) -> Dict[str, 'ScanResult']:
        # Implementation
        pass
```

2. Register in factory function:

```python
def get_scan_strategy(mode: str, config: Config) -> ScanStrategy:
    if mode == "custom":
        return CustomStrategy()
    # ... existing strategies
```

3. Add CLI argument:

```python
parser.add_argument("--mode", choices=["sequential", "batch", "parallel", "custom"])
```

### Adding a New Report Format

1. Find format ID in GVM:
   ```python
   formats = gmp.get_report_formats()
   ```

2. Add to `REPORT_FORMAT_IDS` in `GVMClient`:
   ```python
   REPORT_FORMAT_IDS = {
       "PDF": "c402cc3e-...",
       "NEWFORMAT": "new-uuid-here",
   }
   ```

3. Add to config:
   ```yaml
   report_formats:
     - "PDF"
     - "NEWFORMAT"
   ```

### Custom State Storage

The `StateManager` class can be extended for alternative backends:

```python
class RedisStateManager(StateManager):
    def __init__(self, redis_url: str):
        self.client = redis.from_url(redis_url)

    def _load(self) -> dict:
        return json.loads(self.client.get("scanner_state") or "{}")

    def save(self):
        self.client.set("scanner_state", json.dumps(self.state))
```

---

## License

This project is part of the VulnLab environment for educational and authorized security testing purposes only.

---

## Author

**Maintained by:** [Cristhian Kapelinski](https://github.com/CristhianKapelinski)

Version: 2.0.0
