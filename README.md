# VulnLab — Mass Container Vulnerability Scanner

VulnLab is an automated framework for large-scale discovery and vulnerability auditing of public Docker images. It pulls images from DockerHub, runs each one in a hardened, air-gapped environment, performs a full OpenVAS scan, and saves reports in PDF, XML, CSV, and TXT formats.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Requirements](#3-requirements)
4. [Setup](#4-setup)
5. [Configuration](#5-configuration)
6. [Discovery (Crawler)](#6-discovery-crawler)
7. [Scanner](#7-scanner)
8. [Output Structure](#8-output-structure)
9. [Security Model](#9-security-model)
10. [Database Reference](#10-database-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Overview

VulnLab operates in two independent stages that can run on different machines:

```
[CRAWLER — local machine]           [SCANNER — gpu1/gama]
bin/discovery                       bin/scanner
    │                                   │
    │  DFS over DockerHub API           │  For each image in the job queue:
    │  Collects metadata:               │    1. docker pull
    │  pull_count, stars,               │    2. docker run (hardened, air-gapped)
    │  description, is_official         │    3. Wait for open TCP port
    │                                   │    4. OpenVAS "Full and fast" scan
    ▼                                   │    5. Download PDF/XML/CSV/TXT reports
data/discovery.csv                      │    6. docker stop + docker rmi
data/discovery.jsonl                    ▼
                               data/reports/{image}/
                               data/mass_scan.db
                               data/reports/all_scans_summary.csv
                               data/reports/scan_status.json
```

---

## 2. Architecture

### Directory Layout

```
.
├── bin/
│   ├── scanner          # Scanner orchestrator (Python script)
│   └── discovery        # DockerHub DFS crawler (Python script)
├── config/
│   ├── scanner.yaml.example   # Template — copy to scanner.yaml and fill credentials
│   └── scanner.yaml           # Local config with credentials (gitignored)
├── data/
│   ├── images_all.csv   # Seed image list
│   ├── discovery.csv    # Images collected by the crawler
│   ├── discovery.jsonl  # Full metadata (JSON Lines, one object per image)
│   ├── mass_scan.db     # SQLite job queue (WAL mode)
│   ├── .dfs_state.json  # Crawler checkpoint (completed prefixes)
│   └── reports/         # Scan reports and status
├── logs/
│   ├── mass_scan.log    # Scanner log
│   └── discovery.log    # Crawler log
└── src/
    └── vulnlab/
        ├── core/
        │   ├── container.py    # Docker lifecycle (pull/run/stop/rm)
        │   ├── db.py           # SQLite job queue
        │   └── setup.py        # Environment setup (network + OpenVAS)
        ├── discovery/
        │   └── catalog.py      # FileSource and DockerHubDFSSource
        └── scanner/
            ├── openvas_scanner.py   # GMP client (GVMClient)
            └── worker.py            # Per-image worker (container + GVM)
```

### Scanner Pipeline

```
MassScanner.run()
    │
    ├─ db.reset_stale()          # Reclaim jobs from dead workers (heartbeat > 5 min)
    │
    └─ ThreadPoolExecutor(40)    # 40 container workers in parallel
           │
           └─ ScanWorker.run(job)
                  │
                  ├─ ContainerManager.lifecycle(image)
                  │       ├─ _check_image_size()    # Reject > 10 GB via manifest API
                  │       ├─ pull()                  # docker pull (retry + rate-limit backoff)
                  │       ├─ run()                   # docker run (hardened)
                  │       ├─ probe_reachable()       # Wait for any TCP port to open
                  │       ├─ start_watchdog()        # Kill container if > 1h
                  │       └─ yield (ip, container_id)
                  │               │
                  │         [GVM SEMAPHORE — max 12 concurrent]
                  │               │
                  ├─ gvm.create_target(ip)
                  ├─ gvm.create_task(target_id)
                  ├─ gvm.start_task(task_id)
                  ├─ gvm.wait_for_task()             # Poll every 30s
                  ├─ gvm.get_report_summary()
                  ├─ gvm.get_report(fmt)             # PDF / XML / CSV / TXT
                  └─ [finally] container stop + rm + rmi
```

### DFS Discovery Algorithm

The DockerHub search API caps results at 10,000 per query. The crawler uses a Depth-First Search over the repository prefix space to enumerate every image:

```
crawl("a")
  → API returns 10,000+ results → COLLISION
  → recurse: crawl("aa"), crawl("ab"), ..., crawl("a9")
      crawl("aa") → < 10,000 results → BRANCH COMPLETE → save state
      crawl("ab") → 10,000+ results  → COLLISION
        → recurse: crawl("aba"), crawl("abb"), ...
```

State is saved to `data/.dfs_state.json` after each branch completes. The crawler resumes from where it left off after any restart.

---

## 3. Requirements

### Crawler machine (local)
- Python 3.10+
- `requests`, `pyyaml`

### Scanner machine (gpu1)
- Docker Engine 24+
- Python 3.10+
- `docker`, `python-gvm`, `pyyaml`, `requests`
- 30+ GB free disk space
- 16+ GB RAM recommended (OpenVAS ~4 GB + up to 40 × 512 MB containers)

---

## 4. Setup

```bash
git clone <repo>
cd LabVulnerabilities

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp config/scanner.yaml.example config/scanner.yaml
# Edit config/scanner.yaml and fill in your DockerHub and GVM credentials
```

The scanner automatically starts and configures the OpenVAS Docker container on first run. On a cold start, allow 20–40 minutes for GVM to initialize and load NVT feeds.

---

## 5. Configuration

Copy `config/scanner.yaml.example` to `config/scanner.yaml` (gitignored) and set your values.

### Key parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `container.workers` | `40` | Parallel container workers. GVM tasks are additionally capped to 12 simultaneous by an internal semaphore. |
| `container.dockerhub_username` | `""` | DockerHub account for authenticated pulls (200/6h). Leave empty for anonymous (100/6h per IP). |
| `container.dockerhub_password` | `""` | DockerHub Personal Access Token (PAT). Generate at hub.docker.com → Account Settings → Security. |
| `container.max_image_size_mb` | `10240` | Pre-pull size gate via registry manifest API. Images larger than this are skipped. |
| `container.remove_image_after` | `true` | Run `docker rmi` after each scan to keep disk usage below ~15 GB. |
| `openvas.startup_timeout` | `3600` | Seconds to wait for GVM to initialize on the first run. |
| `port` | `9390` | GMP API port. **Do not use 9392** — that is the HTTPS web UI. |
| `scan_config_name` | `"Full and fast"` | OpenVAS scan profile. |
| `poll_interval` | `30` | Seconds between scan status polls. |
| `cleanup_after_scan` | `true` | Delete GVM task and target after downloading reports. |

---

## 6. Discovery (Crawler)

The crawler runs **locally** and collects images from DockerHub ordered by pull count (requires DockerHub authentication).

### Start

```bash
cd /path/to/LabVulnerabilities

nohup python3 bin/discovery \
  --username YOUR_DOCKERHUB_USERNAME \
  --password YOUR_DOCKERHUB_PAT \
  --csv data/discovery.csv \
  --jsonl data/discovery.jsonl \
  --state data/.dfs_state.json \
  >> logs/discovery.log 2>&1 &
```

The crawler is fully resumable. If it stops for any reason (token expiry, network error), restarting with the same parameters continues from the last completed prefix.

### Monitor

```bash
tail -f logs/discovery.log
wc -l data/discovery.csv
```

### Push new images to the scanner

```bash
rsync -av data/discovery.csv gpu1:~/mass_scanner/data/
ssh gpu1 'cd ~/mass_scanner && venv/bin/python3 bin/scanner \
  --seed --file data/discovery.csv --db data/mass_scan.db'
```

### CLI options

```
bin/discovery [OPTIONS]

  --csv PATH       Output CSV file (default: data/discovery.csv)
  --jsonl PATH     Output JSONL file (default: data/discovery.jsonl)
  --state PATH     Checkpoint file (default: data/.dfs_state.json)
  --username STR   DockerHub username (enables pull_count ordering)
  --password STR   DockerHub Personal Access Token
  --limit N        Maximum images to collect (default: 10,000,000)
```

### Output files

| File | Format | Contents |
|------|--------|----------|
| `data/discovery.csv` | CSV | `image,pull_count,star_count,is_official,is_automated,description` |
| `data/discovery.jsonl` | JSON Lines | Full DockerHub API response object per line |
| `data/.dfs_state.json` | JSON | `{"completed_prefixes": ["a", "aa", ...]}` |

---

## 7. Scanner

The scanner runs on **gpu1/gama** and uses OpenVAS running in Docker.

### Seed the job queue

Populate the database from an image list (idempotent — existing images are skipped):

```bash
ssh gpu1
cd ~/mass_scanner
venv/bin/python3 bin/scanner --seed --file data/images_all.csv --db data/mass_scan.db
```

### Start scanning

```bash
nohup venv/bin/python3 bin/scanner \
  --workers 40 \
  --db data/mass_scan.db \
  --output data/reports \
  -v \
  >> logs/mass_scan.log 2>&1 &
```

### CLI options

```
bin/scanner [OPTIONS]

  --workers N        Parallel container workers (default: 40)
  --db PATH          SQLite job queue (default: data/mass_scan.db)
  --output DIR       Reports directory (default: data/reports)
  --file PATH        Image CSV for --seed
  --seed             Populate the queue from --file before scanning
  --force            Re-queue all failed jobs
  -c, --config PATH  YAML config file (default: config/scanner.yaml)
  -v, --verbose      Enable DEBUG logging
```

### Monitor progress

```bash
# Live log
tail -f ~/mass_scanner/logs/mass_scan.log

# JSON status snapshot (updated every 30s)
cat ~/mass_scanner/data/reports/scan_status.json

# Database stats
sqlite3 data/mass_scan.db "SELECT status, COUNT(*) FROM jobs GROUP BY status;"

# Top images by vulnerability count
sqlite3 data/mass_scan.db \
  "SELECT image, vuln_high, vuln_medium, vuln_low, vuln_total
   FROM jobs WHERE status='done'
   ORDER BY vuln_total DESC LIMIT 20;"

# Re-queue failed jobs
venv/bin/python3 bin/scanner --force --db data/mass_scan.db
```

### Resuming after a stop

The scanner is fully stateful. On restart, it automatically reclaims any jobs that were left in `running` state (heartbeat timeout > 5 minutes) and continues from the next pending image. No image is ever scanned twice.

---

## 8. Output Structure

```
data/reports/
├── scan_status.json                         ← Global status, updated every 30s
├── all_scans_summary.csv                    ← One row per completed scan
│
├── nginx__latest/
│   └── scan_nginx__latest_20260331_003344/
│       ├── scan_nginx__latest_20260331_003344.pdf
│       ├── scan_nginx__latest_20260331_003344.xml
│       ├── scan_nginx__latest_20260331_003344.csv
│       ├── scan_nginx__latest_20260331_003344.txt
│       └── scan_info.csv                    ← Per-scan metadata
│
└── wordpress__latest/
    └── scan_wordpress__latest_20260331_041122/
        └── ...
```

### `scan_status.json`

```json
{
  "updated_at": "2026-03-31T00:33:44",
  "progress_pct": 7.2,
  "total": 315845,
  "done": 15680,
  "running": 40,
  "failed": 6,
  "skipped": 3210,
  "pending": 296909,
  "reports_dir": "/home/cristhian/mass_scanner/data/reports",
  "db_path": "/home/cristhian/mass_scanner/data/mass_scan.db",
  "summary_csv": "/home/cristhian/mass_scanner/data/reports/all_scans_summary.csv",
  "workers": 40,
  "machine": "gama"
}
```

`skipped` counts images permanently excluded from scanning (not a service, manifest not found, exited on startup). These never consume GVM resources or retry slots.

### `all_scans_summary.csv` columns

`image, image_slug, container_id, container_ip, scan_date, scan_timestamp, gvm_task_id, gvm_target_id, gvm_report_id, vuln_high, vuln_medium, vuln_low, vuln_log, vuln_total, reports_saved, reports_dir, worker_id`

`vuln_log` counts OpenVAS log-level findings (CVSS = 0, severity `g` in GVM filter `levels=chmlgf`). These are informational detections with no exploitability score — open ports, identified services, OS fingerprints — but are included for completeness.

---

## 9. Security Model

Every scanned container runs with the following restrictions:

| Restriction | Value | Purpose |
|-------------|-------|---------|
| `--cap-drop ALL` | All capabilities dropped | Prevents privilege escalation |
| `--security-opt no-new-privileges` | Enabled | Blocks SUID/SGID elevation |
| `--read-only` | Root filesystem read-only | Prevents filesystem modification |
| `--tmpfs /tmp,/run,/var/run` | `noexec,nosuid` | Allows writes, blocks binary execution |
| `--memory 512m` | 512 MB RAM limit | Prevents host DoS |
| `--cpu-quota 100000` | 1 CPU maximum | Prevents host CPU exhaustion |
| `--pids-limit 256` | 256 processes max | Prevents fork bomb |
| `--ulimit nofile=1024` | 1024 file descriptors | Prevents FD exhaustion |
| `--network trabalho_vulnnet` | Internal bridge | Full network air-gap |

### Network isolation (`trabalho_vulnnet`)

```
internal=True     → No default gateway. Containers cannot make outbound connections,
                    phone home, exfiltrate data, or download additional payloads.

enable_icc=true   → OpenVAS can reach target containers on the same network.

No -p flags       → No ports mapped to the host. Containers are unreachable from outside.
```

**OpenVAS** is connected to two networks simultaneously:
- `bridge` (172.17.0.2) → internet access for NVT feed updates
- `trabalho_vulnnet` (172.30.0.2) → reaches scan targets

The **GMP API (port 9390)** is bound to `127.0.0.1` only — inaccessible from any network.

### GVM concurrency

An internal semaphore (`GVM_MAX_CONCURRENT = 12`) in `worker.py` limits simultaneous active GVM scan tasks regardless of the number of container workers. This prevents `ospd-openvas` from being overwhelmed, which would cause the scanner daemon to lose its internal IPC socket.

---

## 10. Database Reference

### Schema (`data/mass_scan.db`)

```sql
CREATE TABLE jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    image        TEXT NOT NULL UNIQUE,
    name         TEXT,
    status       TEXT DEFAULT 'pending',
    -- pending  → waiting to be claimed
    -- running  → actively being scanned (heartbeat updated every 60s)
    -- done     → scan completed, reports saved
    -- failed   → scan failed, will be retried up to 3 times
    -- skipped  → permanent failure (image not a service, manifest not found,
    --            exited immediately); never retried
    worker_id    TEXT,
    container_id TEXT,
    container_ip TEXT,
    task_id      TEXT,
    target_id    TEXT,
    report_id    TEXT,
    reports_path TEXT,
    attempt      INTEGER DEFAULT 0,
    started_at   TEXT,
    finished_at  TEXT,
    heartbeat_at TEXT,   -- Updated every 60s; jobs silent > 5min are reclaimed
    error        TEXT,
    vuln_high    INTEGER DEFAULT 0,
    vuln_medium  INTEGER DEFAULT 0,
    vuln_low     INTEGER DEFAULT 0,
    vuln_total   INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now'))
);
```

### Useful queries

```sql
-- Overall status
SELECT status, COUNT(*) AS n FROM jobs GROUP BY status;

-- Most vulnerable images
SELECT image, vuln_high, vuln_medium, vuln_low, vuln_total
FROM jobs WHERE status='done'
ORDER BY vuln_total DESC LIMIT 20;

-- Failure breakdown by type
SELECT
  CASE
    WHEN error LIKE '%not found%'          THEN 'manifest_missing'
    WHEN error LIKE '%exited immediately%' THEN 'not_a_service'
    WHEN error LIKE '%exited during%'      THEN 'crash_on_startup'
    WHEN error LIKE '%rate%'               THEN 'rate_limited'
    ELSE 'other'
  END AS error_type,
  COUNT(*) AS n
FROM jobs WHERE status='failed'
GROUP BY error_type ORDER BY n DESC;

-- Images with high-severity vulnerabilities
SELECT image, container_ip, vuln_high, reports_path
FROM jobs WHERE status='done' AND vuln_high > 0
ORDER BY vuln_high DESC;
```

---

## 11. Troubleshooting

### `ospd-openvas` socket lost / `Connection lost with the scanner`

The `ospd-openvas` process inside the container crashed. This happens when the scanner is interrupted while GVM tasks are active, causing the Python multiprocessing manager's internal socket to be lost.

```bash
# Stop the Python scanner
kill $(pgrep -f "bin/scanner")

# Remove any running scan containers
docker ps -q --filter "name=ms_" | xargs -r docker rm -f

# Restart OpenVAS (~3 min to fully initialize)
docker restart openvas_massscan

# Wait for: "Healthchecks completed with no issues"
docker logs -f openvas_massscan 2>&1 | grep -E "Health|Starting OSPd|VTs were up"

# Restart the scanner
cd ~/mass_scanner
nohup venv/bin/python3 bin/scanner --workers 40 \
  --db data/mass_scan.db --output data/reports -v \
  >> logs/mass_scan.log 2>&1 &
```

### OpenVAS not reaching containers (tasks stay `Requested`)

Verify OpenVAS is connected to the scan network:

```bash
docker inspect openvas_massscan | python3 -c \
  "import json,sys; d=json.load(sys.stdin)[0]
   [print(k, v['IPAddress']) for k,v in d['NetworkSettings']['Networks'].items()]"
```

Expected output: both `bridge` and `trabalho_vulnnet`. If `trabalho_vulnnet` is missing:

```bash
docker network connect trabalho_vulnnet openvas_massscan
```

### DockerHub rate limit (429)

Configure `dockerhub_username` and `dockerhub_password` in `config/scanner.yaml` with a Personal Access Token from hub.docker.com → Account Settings → Security.

### Redis `vm.overcommit_memory` warning

Redis prints a warning and may fail to perform background saves (`BGSAVE`) when the Linux kernel has `vm.overcommit_memory = 0` (the default). In that mode the kernel refuses memory allocation if there is not enough free RAM to satisfy the full request, even though Redis only needs a fork for the snapshot. With `vm.overcommit_memory = 1` the kernel always grants the allocation optimistically, which is required for Redis's copy-on-write fork to succeed reliably.

This setting must be applied on the **host machine** (not inside the container) because kernel parameters are shared across all containers on the same host.

```bash
# Apply immediately (takes effect without reboot)
sudo sysctl -w vm.overcommit_memory=1

# Persist across reboots
echo 'vm.overcommit_memory = 1' | sudo tee /etc/sysctl.d/99-vulnlab.conf
```

### About the failure and skip rate

A significant portion of public DockerHub images are not network services and cannot be scanned. The scanner distinguishes two outcomes:

**`skipped`** — permanent, never retried:
- Images deleted from DockerHub since the crawl (`manifest unknown`)
- Non-service images: CLI tools, build images, one-shot scripts that exit with code 0 or 1 immediately on startup
- Images that crash on startup due to missing external dependencies or environment variables
- Images too large to pull (> 10 GB, configurable via `max_image_size_mb`)

**`failed`** — transient, retried up to 3 times:
- Docker API errors (daemon overloaded, network hiccup)
- DockerHub rate limit (HTTP 429) — backed off automatically
- GVM connection errors (ospd socket lost, gvmd crash)

The scanner first attempts to run the container with a read-only root filesystem. If the container exits immediately due to this restriction, it automatically retries with a writable filesystem (all other security restrictions remain — `cap_drop ALL`, `no-new-privileges`, network isolation, PID limit).

```bash
# Re-queue all failed (not skipped) jobs
venv/bin/python3 bin/scanner --force --db data/mass_scan.db
```

---

## References

- DockerHub Search API: `https://hub.docker.com/v2/search/repositories`
- GVM Python Library: `python-gvm`
- OpenVAS Docker image: `immauss/openvas` (Docker Hub)
- Greenbone Management Protocol (GMP): v26
