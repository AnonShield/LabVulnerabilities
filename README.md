# VulnLab — Mass Container Vulnerability Scanner

VulnLab é um framework automatizado de descoberta e auditoria de vulnerabilidades em imagens Docker públicas em larga escala. Para cada imagem da fila de trabalho, ele executa o container em um ambiente endurecido e isolado em rede, realiza um scan completo com OpenVAS via protocolo GMP, e salva os relatórios em PDF, XML, CSV e TXT. O sistema foi projetado para reprodutibilidade científica: todo scan é auditável, toda falha é registrada com motivo, e a execução continua exatamente de onde parou após qualquer interrupção.

---

## Índice

1. [Visão Geral](#1-visão-geral)
2. [Arquitetura do Sistema](#2-arquitetura-do-sistema)
3. [Requisitos](#3-requisitos)
4. [Instalação Passo a Passo](#4-instalação-passo-a-passo)
5. [Configuração Completa](#5-configuração-completa)
6. [Fontes de Imagens — Integração com DITector](#6-fontes-de-imagens--integração-com-ditector)
7. [Executando o Scanner](#7-executando-o-scanner)
8. [Monitoramento em Tempo Real](#8-monitoramento-em-tempo-real)
9. [Estrutura de Saída](#9-estrutura-de-saída)
10. [Modelo de Segurança e Isolamento](#10-modelo-de-segurança-e-isolamento)
11. [Referência do Banco de Dados](#11-referência-do-banco-de-dados)
12. [Referência de Código — Internos](#12-referência-de-código--internos)
13. [Implantação Multi-Máquina](#13-implantação-multi-máquina)
14. [Solução de Problemas](#14-solução-de-problemas)
15. [Referências](#15-referências)

---

## 1. Visão Geral

### O que o VulnLab faz

O VulnLab opera em duas fases independentes que podem ser executadas em máquinas diferentes:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ FASE 1 — DESCOBERTA (máquina local ou DITector)                              │
│                                                                              │
│  DITector crawl → build → rank                                               │
│       │                                                                      │
│       └─ data/ditector_results.jsonl                                         │
│              (imagens rankeadas por peso de dependência na supply chain)     │
└──────────────────────────────────────────────────────────────────────────────┘
                              │
                              │  bin/scanner --seed --source ditector
                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ FASE 2 — SCAN (máquina remota — gpu1, requer 40+ GB RAM para OpenVAS)        │
│                                                                              │
│  Para cada imagem na fila de trabalho (SQLite):                              │
│                                                                              │
│    1. docker pull (com retry e backoff em 429)                               │
│    2. docker run (endurecido: cap_drop ALL, read-only, isolado em rede)      │
│    3. Aguarda porta TCP aberta (prova que o serviço está vivo)               │
│    4. OpenVAS "Full and fast" scan via GMP                                   │
│    5. Baixa relatórios: PDF + XML + CSV + TXT                                │
│    6. docker stop + docker rm + docker rmi                                   │
│                                                                              │
│  Saída:                                                                      │
│    data/reports/{image}/scan_{image}_{timestamp}/  ← relatórios por imagem  │
│    data/reports/all_scans_summary.csv              ← resumo global           │
│    data/mass_scan.db                               ← fila SQLite persistente │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Por que usar o VulnLab para pesquisa

| Propriedade | Descrição |
|-------------|-----------|
| **Reprodutibilidade** | Todo scan gera `scan_info.csv` com timestamp, ID do container, IP, IDs GVM e contagem de vulnerabilidades. Nenhum resultado se perde. |
| **Auditabilidade** | Motivo de cada falha ou skip registrado em log e no banco. Logs em nível DEBUG garantem rastreabilidade completa. |
| **Resiliência** | Heartbeat a cada 60s. Jobs silenciosos por >5 min são automaticamente re-enfileirados. Reiniciar o scanner nunca re-escaneia uma imagem já concluída. |
| **Segurança** | Containers rodados com todos os recursos mínimos necessários. Rede interna (sem gateway). Sem risco de exfiltração, phone-home ou evasão. |
| **Escala** | 40 workers paralelos com semáforo interno limitando o GVM a 12 tasks simultâneas. Testado com listas de >300.000 imagens. |
| **Priorização** | Integração nativa com DITector para priorizar imagens pela criticidade na supply chain Docker, não apenas pela popularidade. |

---

## 2. Arquitetura do Sistema

### Layout de Diretórios

```
LabVulnerabilities/
│
├── bin/
│   └── scanner                      # Ponto de entrada principal (Python)
│
├── config/
│   ├── scanner.yaml.example         # Template — copie para scanner.yaml
│   └── scanner.yaml                 # Configuração local (gitignored)
│
├── data/
│   ├── ditector_results.jsonl       # Lista priorizada gerada pelo DITector
│   ├── batch_min.jsonl              # Batch mínimo para testes (3 imagens)
│   ├── images_all.csv               # Lista seed alternativa (formato CSV)
│   ├── mass_scan.db                 # Fila SQLite WAL (job queue persistente)
│   └── reports/                     # Relatórios e status
│       ├── scan_status.json         # Status global (atualizado a cada 30s)
│       ├── all_scans_summary.csv    # Uma linha por scan concluído
│       ├── logs/                    # Logs do scanner (DEBUG, um arquivo por sessão)
│       └── {image_slug}/
│           └── scan_{slug}_{ts}/
│               ├── scan_{slug}_{ts}.pdf
│               ├── scan_{slug}_{ts}.xml
│               ├── scan_{slug}_{ts}.csv
│               ├── scan_{slug}_{ts}.txt
│               └── scan_info.csv    # Metadados do scan individual
│
├── requirements.txt
│
└── src/
    └── vulnlab/
        ├── core/
        │   ├── container.py         # Ciclo de vida Docker (pull/run/probe/stop/rm)
        │   ├── db.py                # Fila SQLite (ScanDB)
        │   └── setup.py             # Provisionamento automático (rede + OpenVAS)
        ├── discovery/
        │   └── catalog.py           # Fontes de imagem (DITectorSource, FileSource)
        └── scanner/
            ├── openvas_scanner.py   # Cliente GMP (GVMClient, Config)
            └── worker.py            # Worker por imagem (ScanWorker)
```

### Pipeline de Scan — Fluxo Completo

```
bin/scanner
    │
    ├─ EnvironmentSetup.run()
    │       ├─ Cria rede Docker interna "trabalho_vulnnet" (se não existir)
    │       ├─ Inicia container OpenVAS "openvas_massscan" (se não estiver rodando)
    │       ├─ Conecta OpenVAS à rede "trabalho_vulnnet"
    │       └─ Aguarda GVM inicializar (porta 9390 + socket ospd)
    │
    ├─ db.seed()                     # Popula a fila com imagens do source
    │
    ├─ db.reset_stale()              # Reclama jobs parados (heartbeat > 5 min)
    │
    └─ MassScanner.run()
           │
           └─ ThreadPoolExecutor(workers=40)
                  │
                  └─ ScanWorker.run(job)       ← uma thread por imagem
                         │
                         ├─ ContainerManager.lifecycle(image)   ← @contextmanager
                         │       ├─ _check_size()    # Rejeita > 10 GB via manifest API
                         │       ├─ pull()            # Retry com backoff em 429
                         │       ├─ run()             # docker run endurecido
                         │       ├─ Verifica status   # Retry com RW se exited (1/126/127)
                         │       ├─ probe()           # Aguarda TCP em qualquer porta
                         │       └─ yield ip, cid, skip_reason
                         │
                         ├─ [_GVM_SEM — máx. 12 simultâneos]
                         │       ├─ gvm.create_target(ip)
                         │       ├─ gvm.create_task(target_id)
                         │       ├─ gvm.start_task(task_id)
                         │       ├─ gvm.wait_for_task()      # Poll a cada 30s
                         │       └─ gvm.get_report_summary() # CVSS por severidade
                         │
                         ├─ _save()                  # PDF/XML/CSV/TXT + scan_info.csv
                         │
                         └─ [finally] container stop + rm + rmi + prune periódico
```

### Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────┐
│                    Host (gpu1)                           │
│                                                         │
│  ┌──────────────────┐   ┌──────────────────────────┐   │
│  │   bin/scanner    │   │    openvas_massscan       │   │
│  │  (Python process)│   │  (Docker: immauss/openvas)│   │
│  │                  │   │                           │   │
│  │  40 threads      │   │  gvmd + ospd-openvas      │   │
│  │  │               │   │  Redis + PostgreSQL        │   │
│  │  │ GMP/TLS:9390  │──▶│  127.0.0.1:9390           │   │
│  └──┼───────────────┘   └──────────┬────────────────┘   │
│     │                              │ trabalho_vulnnet    │
│     │  docker API (unix socket)    │ 172.30.0.2          │
│     ▼                              │                     │
│  ┌──────────────────────────────┐  │                     │
│  │   ms_nginx__latest_abc123    │  │                     │
│  │   (container sob scan)       │◀─┘  OpenVAS escaneia   │
│  │   172.30.0.x                 │                        │
│  │   --cap-drop ALL             │                        │
│  │   --read-only                │                        │
│  │   --network trabalho_vulnnet │                        │
│  └──────────────────────────────┘                        │
│                                                         │
│  ┌──────────────────────────────┐                        │
│  │   data/mass_scan.db          │                        │
│  │   (SQLite WAL — job queue)   │                        │
│  └──────────────────────────────┘                        │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Requisitos

### Máquina Scanner (gpu1 — remota)

| Componente | Requisito mínimo | Notas |
|------------|-----------------|-------|
| SO | Linux (Ubuntu 20.04+) | Testado em Ubuntu 22.04 |
| Docker Engine | 24.0+ | `docker info` deve funcionar sem sudo |
| Python | 3.10+ | `python3 --version` |
| RAM | 40 GB+ | OpenVAS usa ~8–15 GB. Cada container: 512 MB. Com 40 workers: 40 × 512 MB = 20 GB. |
| Disco | 50 GB+ livres | Relatórios PDF/XML por scan, imagens Docker temporárias |
| CPU | 8+ cores | 40 workers I/O-bound; mais cores permitem mais throughput |
| Rede | Acesso à internet | Para `docker pull` e atualização de feeds NVT do OpenVAS |

### Máquina Local (descoberta / controle)

| Componente | Requisito |
|------------|-----------|
| Python | 3.10+ |
| Pacotes | `requests`, `pyyaml` |
| Opcional | DITector (Go 1.20+, MongoDB, Neo4j) para priorização |

---

## 4. Instalação Passo a Passo

### 4.1 Clonar o repositório

```bash
git clone <repo-url>
cd LabVulnerabilities
```

### 4.2 Criar ambiente virtual Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

O `requirements.txt` inclui:
- `docker` — SDK Python para Docker Engine
- `python-gvm` / `gvm-tools` — cliente GMP para OpenVAS
- `pyyaml` — leitura de configuração
- `requests` — verificação de tamanho de imagem via API do registro

### 4.3 Configurar credenciais

```bash
cp config/scanner.yaml.example config/scanner.yaml
# Edite config/scanner.yaml — veja seção 5 para referência completa
```

O arquivo `config/scanner.yaml` está no `.gitignore` e nunca será commitado.

### 4.4 Verificar Docker

```bash
# Verificar que Docker está acessível sem sudo
docker info
docker ps

# Se precisar de sudo, adicione seu usuário ao grupo docker
sudo usermod -aG docker $USER
# Faça logout e login para o grupo ter efeito
```

### 4.5 Inicializar o ambiente (primeira execução)

```bash
# O scanner provisiona tudo automaticamente na primeira execução:
# - Cria a rede Docker interna "trabalho_vulnnet"
# - Faz pull e inicia o container OpenVAS
# - Aguarda o GVM inicializar (20-40 minutos no primeiro boot)
# --wait-only encerra após o GVM estar pronto, sem iniciar scans
venv/bin/python3 bin/scanner --wait-only -c config/scanner.yaml
```

Para monitorar a inicialização do OpenVAS:
```bash
docker logs -f openvas_massscan 2>&1 | grep -E "Health|Starting OSPd|VTs were up|Greenbone"
```

Você verá mensagens como:
```
Healthchecks completed with no issues found.
Starting OSPd OpenVAS 22.x.x
VTs were up to date. No synchronization needed.
```

### 4.6 Popular a fila de trabalho (seed)

```bash
# A partir de arquivo DITector (recomendado para pesquisa)
venv/bin/python3 bin/scanner --seed \
  --source ditector \
  --file data/ditector_results.jsonl \
  -c config/scanner.yaml

# A partir de arquivo CSV simples
venv/bin/python3 bin/scanner --seed \
  --source file \
  --file data/images_all.csv \
  -c config/scanner.yaml
```

O seed é **idempotente**: imagens já existentes na fila são ignoradas silenciosamente.

### 4.7 Iniciar o scanner

```bash
nohup venv/bin/python3 bin/scanner \
  --workers 40 \
  --db data/mass_scan.db \
  --output data/reports \
  -c config/scanner.yaml \
  -v \
  >> data/reports/logs/launch.log 2>&1 &

echo "PID=$!"
```

---

## 5. Configuração Completa

Copie `config/scanner.yaml.example` para `config/scanner.yaml` e ajuste os valores.

### 5.1 Referência completa do `scanner.yaml`

```yaml
# ── Catálogo de imagens ──────────────────────────────────────────────────────
catalog:
  source: "ditector"        # "ditector" | "file"
                            # ditector: lê data/ditector_results.jsonl (ImageWeight)
                            # file: lê CSV com coluna "image" ou TXT uma-por-linha
  file: "data/ditector_results.jsonl"
  limit: 100000             # Limite de imagens a importar no seed (0 = sem limite)

# ── OpenVAS (provisionamento automático) ─────────────────────────────────────
openvas:
  image: "immauss/openvas:latest"
  container_name: "openvas_massscan"
  startup_timeout: 3600     # Segundos para aguardar o GVM na primeira inicialização.
                            # O primeiro boot baixa e indexa feeds NVT (~20-40 min).
                            # Reinicializações subsequentes levam ~3-5 min.

# ── Containers sob scan ──────────────────────────────────────────────────────
container:
  network: "trabalho_vulnnet"       # Nome da rede Docker interna (criada automaticamente)
  network_subnet: "172.30.0.0/16"   # Sub-rede CIDR da rede interna
  startup_wait: 20                  # Segundos de espera após o container iniciar
                                    # antes de verificar a saúde. Aumentar para
                                    # imagens com inicialização lenta (ex.: bancos).
  health_timeout: 90                # Segundos máximos para aguardar uma porta TCP
                                    # abrir. Imagens que não abrem porta dentro deste
                                    # prazo são marcadas como "skipped".
  scan_watchdog: 3600               # Segundos máximos de vida de um container.
                                    # Mata containers que ficam vivos além deste prazo
                                    # (proteção contra containers zumbi).
  stop_timeout: 10                  # Segundos de grace period no docker stop antes
                                    # de enviar SIGKILL.
  pull_retries: 3                   # Tentativas de docker pull antes de desistir.
  pull_retry_delay: 60              # Segundos entre tentativas de pull em 429/erro.
  max_image_size_mb: 10240          # Tamanho máximo de imagem aceito (MB).
                                    # Verificado via API do registro antes do pull.
                                    # Imagens maiores são marcadas como "skipped".
                                    # 0 = sem limite.
  remove_image_after: true          # Remove a imagem Docker após o scan.
                                    # Mantém o uso de disco abaixo de ~15 GB.
                                    # Desativar apenas para debugging.
  prune_every: 20                   # A cada N scans, executa docker container prune
                                    # e docker image prune --dangling para liberar disco.
  mem_limit: "512m"                 # Limite de memória RAM por container (Docker --memory).
  cpu_quota: 100000                 # Quota de CPU em microssegundos por período de 100ms.
                                    # 100000 = 1 CPU inteiro. 50000 = 0.5 CPU.
  pids_limit: 256                   # Limite de processos simultâneos por container.
  ulimit_nofile: 1024               # Limite de file descriptors por container.
  read_only_rootfs: true            # Monta o rootfs em modo somente-leitura.
                                    # Se o container sair com erro (1/126/127), o scanner
                                    # tenta novamente com RW — todas as outras restrições
                                    # permanecem (cap_drop, rede, etc.).
  drop_all_caps: true               # --cap-drop ALL: remove todas as capabilities Linux.
  no_new_privileges: true           # --security-opt no-new-privileges: bloqueia SUID/SGID.

  # DockerHub — aumenta o limite de pulls de 100 para 200 por 6 horas por conta.
  # Gere um Personal Access Token em: hub.docker.com → Account Settings → Security
  dockerhub_username: ""
  dockerhub_password: ""            # Use o token PAT, não a senha da conta.

# ── Execução ─────────────────────────────────────────────────────────────────
execution:
  workers: 40                       # Workers paralelos de container.
                                    # Cada worker é uma thread Python com seu próprio
                                    # ScanWorker (GVMClient + ContainerManager).
                                    # O GVM é adicionalmente limitado a 12 tasks
                                    # simultâneas pelo semáforo _GVM_SEM em worker.py.
  max_retries: 3                    # Máximo de tentativas antes de marcar como "failed".

# ── GVM (Greenbone Vulnerability Manager) ────────────────────────────────────
host: "127.0.0.1"                   # GMP só aceita conexões de localhost (segurança).
port: 9390                          # Porta GMP. NÃO usar 9392 (é a Web UI HTTPS).
username: "admin"                   # Usuário GVM.
password: ""                        # Senha do admin GVM. OBRIGATÓRIO preencher.

# ── Perfil de scan ────────────────────────────────────────────────────────────
scan_config_name: "Full and fast"   # Perfil de scan OpenVAS.
                                    # Opções disponíveis (depende da versão):
                                    #   "Full and fast" — completo e rápido (recomendado)
                                    #   "Full and deep" — mais profundo, mais lento
                                    #   "System Discovery" — apenas descoberta de serviços
port_list_name: "All IANA assigned TCP and UDP"
                                    # Lista de portas escaneadas.
                                    # ATENÇÃO: "All IANA assigned TCP and UDP" inclui
                                    # UDP, que é MUITO lento. Para testes rápidos use
                                    # "All IANA assigned TCP" (~10x mais rápido).
scanner_name: "OpenVAS Default"     # Nome do scanner GVM interno.
cleanup_after_scan: true            # Remove task e target do GVM após baixar relatórios.
                                    # Mantém o banco PostgreSQL do GVM limpo em runs longos.
poll_interval: 30                   # Segundos entre polls de status do scan.

# ── Relatórios ────────────────────────────────────────────────────────────────
report_formats:
  - "PDF"                           # Relatório visual legível por humanos.
  - "XML"                           # Formato nativo GVM — parsing programático completo.
  - "CSV"                           # Tabela de vulnerabilidades — análise em planilha.
  - "TXT"                           # Texto plano — grep/awk direto.

output_dir: "./reports_mass"        # Diretório raiz para relatórios (relativo ao CWD).
```

### 5.2 Parâmetros mais importantes

| Parâmetro | Impacto na performance | Impacto na segurança |
|-----------|----------------------|---------------------|
| `execution.workers` | Alto: mais workers = mais containers simultâneos | — |
| `container.health_timeout` | Médio: quanto tempo esperar que o serviço suba | — |
| `port_list_name` | **Crítico**: UDP aumenta tempo de scan 10×+ | — |
| `container.max_image_size_mb` | Médio: limita tempo de pull | Baixo: evita imagens gigantes |
| `container.read_only_rootfs` | Baixo | Alto: bloqueia gravações no FS |
| `container.drop_all_caps` | Nenhum | **Crítico**: principal proteção do host |
| `cleanup_after_scan` | Médio: libera disco GVM | — |

---

## 6. Fontes de Imagens — Integração com DITector

### 6.1 Por que usar DITector

Uma abordagem ingênua para selecionar imagens para scan seria pegar as mais populares (maior `pull_count`). O problema: uma imagem com 1 bilhão de pulls pode ser um executável CLI de desenvolvimento que nunca roda em produção. O VulnLab usa o DITector para selecionar imagens pela sua **criticidade estrutural na supply chain Docker** — imagens que são base para muitas outras imagens têm impacto de vulnerabilidade muito maior.

### 6.2 Formato DITector (`ditector_results.jsonl`)

Cada linha é um objeto JSON com a estrutura `ImageWeight` produzida pelo script `calculate-node-weights` do DITector:

```json
{"repository_namespace": "library", "repository_name": "nginx", "tag_name": "latest", "weights": 95420}
{"repository_namespace": "library", "repository_name": "redis", "tag_name": "7.0", "weights": 82100}
{"repository_namespace": "bitnami", "repository_name": "postgresql", "tag_name": "15", "weights": 61300}
```

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `repository_namespace` | string | Namespace DockerHub (ex: `library`, `bitnami`) |
| `repository_name` | string | Nome do repositório (ex: `nginx`) |
| `tag_name` | string | Tag da imagem (ex: `latest`, `7.0`) |
| `weights` | int | Score de criticidade calculado pelo DITector |

A imagem completa é montada como `{namespace}/{name}:{tag}`. Para namespace `library`, equivale ao nome canônico (ex: `library/nginx:latest` = `nginx:latest`).

### 6.3 Fluxo completo DITector → VulnLab

```bash
# 1. No DITector: gerar dataset priorizado
./ditector crawl --workers 50 --accounts accounts.json --config config.yaml
./ditector build --format mongo --threshold 0 --tags 2 --config config.yaml
./ditector execute --script calculate-node-weights --threshold 0 \
    --file ditector_results.jsonl --config config.yaml

# 2. Copiar para LabVulnerabilities
cp ditector_results.jsonl /path/to/LabVulnerabilities/data/

# 3. Seed e scan
venv/bin/python3 bin/scanner --seed --source ditector \
    --file data/ditector_results.jsonl -c config/scanner.yaml
venv/bin/python3 bin/scanner --workers 40 --db data/mass_scan.db \
    --output data/reports -c config/scanner.yaml -v &
```

### 6.4 Fonte alternativa: arquivo CSV

Para usar uma lista manual de imagens:

```csv
image,pull_count
nginx:latest,1000000000
redis:7.0,500000000
postgres:15,300000000
```

```bash
venv/bin/python3 bin/scanner --seed --source file \
    --file data/minhas_imagens.csv -c config/scanner.yaml
```

O `pull_count` no CSV é usado para priorizar a ordem de scan (maiores primeiro). Pode ser 0 se não for relevante.

---

## 7. Executando o Scanner

### 7.1 Referência completa da CLI

```
bin/scanner [OPÇÕES]

Opções de fila:
  --seed                  Popula o banco com imagens do source antes de escanear.
                          Idempotente: imagens já existentes são ignoradas.
  --source SOURCE         Fonte de imagens: "ditector" | "file" (padrão: "file")
  --file PATH             Caminho para o arquivo de imagens (CSV ou JSONL)
  --force                 Re-enfileira jobs em status "failed" e "skipped"
                          para uma nova tentativa.
  --watch                 Modo contínuo: re-lê o arquivo source a cada 60s
                          e adiciona novas imagens à fila automaticamente.

Execução:
  --workers N             Workers paralelos (padrão: 40)
  --db PATH               Caminho do SQLite (padrão: data/mass_scan.db)
  --output DIR            Diretório de relatórios (padrão: data/reports)
  --wait-only             Apenas espera o GVM inicializar e sai.
                          Útil para verificar a saúde do ambiente.

GVM (sobrescreve config.yaml):
  --host HOST             Host GVM (padrão: 127.0.0.1)
  --port PORT             Porta GMP (padrão: 9390)
  --user USER             Usuário GVM (padrão: admin)
  --pw PW                 Senha GVM

Global:
  -c, --config PATH       Arquivo YAML de configuração (padrão: config/scanner.yaml)
  -v, --verbose           Habilita logging DEBUG no console (arquivos sempre em DEBUG)
```

### 7.2 Casos de uso comuns

**Scan completo padrão:**
```bash
nohup venv/bin/python3 bin/scanner \
  --workers 40 \
  --db data/mass_scan.db \
  --output data/reports \
  -c config/scanner.yaml -v \
  >> data/reports/logs/run.log 2>&1 &
```

**Seed + scan em um comando:**
```bash
venv/bin/python3 bin/scanner \
  --seed --source ditector --file data/ditector_results.jsonl \
  --workers 40 --output data/reports -c config/scanner.yaml -v &
```

**Teste mínimo (3 imagens conhecidas):**
```bash
venv/bin/python3 bin/scanner \
  --seed --source ditector --file data/batch_min.jsonl \
  --workers 3 --output data/reports_test -c config/scanner.yaml -v
```

**Re-executar jobs falhos:**
```bash
# Re-enfileira failed E skipped
venv/bin/python3 bin/scanner --force --db data/mass_scan.db

# Apenas failed (sem tocar skipped)
sqlite3 data/mass_scan.db \
  "UPDATE jobs SET status='pending' WHERE status='failed';"

# Resumir o scan após re-enfileirar
venv/bin/python3 bin/scanner --workers 40 --output data/reports \
  -c config/scanner.yaml -v &
```

**Modo watch (para pipelines contínuos):**
```bash
# Fica rodando indefinidamente, checando novas imagens a cada 60s
venv/bin/python3 bin/scanner \
  --watch --source ditector --file data/ditector_results.jsonl \
  --workers 40 --output data/reports -c config/scanner.yaml -v &
```

### 7.3 Retomada após interrupção

O scanner é **completamente stateful**. Para retomar após qualquer interrupção (kill, crash, reinicialização do host):

```bash
# Basta rodar novamente — o scanner automaticamente:
# 1. Reclama jobs em status "running" com heartbeat > 5 min (eram orphaned)
# 2. Continua a partir dos primeiros "pending" da fila
# 3. Nunca re-escaneia status "done"
venv/bin/python3 bin/scanner --workers 40 --output data/reports \
  -c config/scanner.yaml -v &
```

Não há nenhum flag especial para retomar — é o comportamento padrão.

---

## 8. Monitoramento em Tempo Real

### 8.1 Logs

O arquivo de log é criado em `data/reports/logs/scanner_YYYYMMDD_HHMMSS.log` a cada nova sessão, **sempre em nível DEBUG** independente de `--verbose`, para garantir rastreabilidade científica completa.

```bash
# Acompanhar log em tempo real
tail -f data/reports/logs/scanner_*.log | grep -E "DONE|FAIL|SKIP|ERROR"

# Ver apenas vulnerabilidades encontradas
grep "DONE" data/reports/logs/scanner_*.log | grep -v "vulns: 0"

# Contar 429 rate limits do DockerHub
grep -c "429\|rate" data/reports/logs/scanner_*.log
```

### 8.2 Status JSON (atualizado a cada 30s)

```bash
cat data/reports/scan_status.json | python3 -m json.tool
```

Exemplo de saída:
```json
{
  "at": "Thu Apr  3 08:45:12 2026",
  "pct": 7.2,
  "pending": 296909,
  "running": 40,
  "done": 15680,
  "failed": 6,
  "skipped": 3210,
  "total": 315845,
  "machine": "gpu1"
}
```

### 8.3 Queries SQLite diretas

```bash
# Abrir banco interativo
sqlite3 data/mass_scan.db

# Status geral
SELECT status, COUNT(*) AS n FROM jobs GROUP BY status;

# Progresso percentual
SELECT
  ROUND(100.0 * SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) / COUNT(*), 2)
    AS pct_done,
  COUNT(*) AS total
FROM jobs;

# Top 20 imagens mais vulneráveis (por total)
SELECT image, vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_total
FROM jobs
WHERE status = 'done'
ORDER BY vuln_total DESC
LIMIT 20;

# Top 20 por críticas (CVSS >= 9.0)
SELECT image, vuln_critical, vuln_high, vuln_total
FROM jobs
WHERE status = 'done' AND vuln_critical > 0
ORDER BY vuln_critical DESC
LIMIT 20;

# Workers ativos agora
SELECT worker_id, image, started_at, heartbeat_at
FROM jobs
WHERE status = 'running'
ORDER BY started_at;

# Taxa de falha por tipo de erro
SELECT
  CASE
    WHEN error LIKE '%not found%'         THEN 'manifest_missing'
    WHEN error LIKE '%exited%'            THEN 'container_exited'
    WHEN error LIKE '%no_ip%'             THEN 'no_tcp_port_opened'
    WHEN error LIKE '%pull_failed%'       THEN 'pull_failed'
    WHEN error LIKE '%Too large%'         THEN 'image_too_large'
    WHEN error LIKE '%429%'               THEN 'rate_limited'
    WHEN error LIKE '%timeout%'           THEN 'timeout'
    ELSE 'other'
  END AS tipo,
  COUNT(*) AS n
FROM jobs
WHERE status IN ('failed', 'skipped')
GROUP BY tipo
ORDER BY n DESC;

# Imagens com vulnerabilidades críticas e seus relatórios
SELECT image, container_ip, vuln_critical, vuln_high, reports_path
FROM jobs
WHERE status = 'done' AND vuln_critical > 0
ORDER BY vuln_critical DESC;
```

### 8.4 Verificação de containers em execução

```bash
# Ver containers de scan ativos
docker ps --filter "name=ms_" \
  --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"

# Forçar parada de todos os containers de scan (emergência)
docker ps -q --filter "name=ms_" | xargs -r docker rm -f

# Ver uso de disco pelas imagens Docker cacheadas
docker system df
```

---

## 9. Estrutura de Saída

### 9.1 Hierarquia de diretórios

```
data/reports/
│
├── scan_status.json                      ← Status global (atualizado a cada 30s)
├── all_scans_summary.csv                 ← Uma linha por scan concluído
├── logs/
│   └── scanner_20260403_084512.log       ← Log DEBUG completo desta sessão
│
├── library__nginx__latest/               ← slug = re.sub("[^a-zA-Z0-9._-]+", "__", image)
│   └── scan_library__nginx__latest_20260403_091233/
│       ├── scan_library__nginx__latest_20260403_091233.pdf   ← Relatório visual
│       ├── scan_library__nginx__latest_20260403_091233.xml   ← Dados completos GVM
│       ├── scan_library__nginx__latest_20260403_091233.csv   ← Tabela de vulns
│       ├── scan_library__nginx__latest_20260403_091233.txt   ← Texto plano
│       └── scan_info.csv                                     ← Metadados deste scan
│
└── bitnami__redis__7.0/
    └── scan_bitnami__redis__7.0_20260403_093045/
        └── ...
```

### 9.2 `scan_info.csv` — metadados por scan

| Campo | Descrição |
|-------|-----------|
| `image` | Nome completo da imagem (ex: `library/nginx:latest`) |
| `image_slug` | Nome sanitizado para uso em nomes de arquivo/diretório |
| `container_id` | Primeiros 12 chars do ID do container Docker |
| `container_ip` | IP atribuído na rede `trabalho_vulnnet` |
| `scan_date` | Data do scan (`YYYY-MM-DD`) |
| `scan_timestamp` | Timestamp completo (`YYYYMMdd_HHMMSS`) |
| `gvm_task_id` | UUID da task GVM (para referência cruzada com GVM logs) |
| `gvm_target_id` | UUID do target GVM |
| `gvm_report_id` | UUID do relatório GVM (para re-download se necessário) |
| `vuln_critical` | Vulnerabilidades com CVSS ≥ 9.0 |
| `vuln_high` | Vulnerabilidades com CVSS 7.0–8.9 |
| `vuln_medium` | Vulnerabilidades com CVSS 4.0–6.9 |
| `vuln_low` | Vulnerabilidades com CVSS 0.1–3.9 |
| `vuln_log` | Resultados informativos (CVSS = 0; portas abertas, OS fingerprint, etc.) |
| `vuln_total` | Total de todos os níveis de severidade |
| `reports_saved` | Formatos baixados com sucesso (ex: `PDF\|XML\|CSV\|TXT`) |
| `reports_dir` | Caminho absoluto do diretório com os relatórios |
| `worker_id` | Identificador do worker (`hostname-thread_id`) |

### 9.3 Classificação de severidade CVSS

O VulnLab usa a escala CVSS v3 para classificar vulnerabilidades:

| Nível | CVSS Base Score | Campo no banco | Exemplo |
|-------|----------------|----------------|---------|
| Critical | ≥ 9.0 | `vuln_critical` | RCE sem autenticação, CVSS 9.8 |
| High | 7.0 – 8.9 | `vuln_high` | Escalada de privilégio local, CVSS 7.8 |
| Medium | 4.0 – 6.9 | `vuln_medium` | XSS reflexivo, CVSS 6.1 |
| Low | 0.1 – 3.9 | `vuln_low` | Disclosure de versão, CVSS 2.6 |
| Log | 0.0 | `vuln_log` | Porta aberta detectada, OS fingerprint |

O campo `vuln_log` corresponde ao filtro GVM `levels=chmlgf` (log-level) — **não representa vulnerabilidades exploráveis**, mas sim informações sobre serviços e configurações detectadas pelo OpenVAS.

---

## 10. Modelo de Segurança e Isolamento

### 10.1 Restrições por container

Cada container sob scan é criado com as seguintes restrições impostas pelo `ContainerManager`:

| Flag Docker | Valor | Proteção |
|-------------|-------|----------|
| `--cap-drop` | `ALL` | Remove **todas** as capabilities Linux. O container não pode chamar privileged syscalls, montar filesystems, modificar interfaces de rede, ou usar raw sockets. |
| `--security-opt` | `no-new-privileges:true` | Impede que qualquer processo dentro do container ganhe privilégios adicionais via SUID/SGID bits ou chamadas de sistema `execve`. |
| `--read-only` | — | Sistema de arquivos raiz somente-leitura. O container não pode modificar nenhum arquivo do seu FS. |
| `--tmpfs /tmp` | `rw,noexec,nosuid,size=64m` | Permite escrita em /tmp mas **bloqueia execução de binários** escritos ali (noexec). |
| `--tmpfs /run` | `rw,noexec,nosuid,size=32m` | Idem para /run. |
| `--tmpfs /var/run` | `rw,noexec,nosuid,size=32m` | Idem para /var/run. |
| `--memory` | `512m` | Limite de RAM. Previne DoS no host por consumo excessivo de memória. |
| `--cpu-quota` | `100000` | Equivalente a 1 CPU inteiro. Previne starvation do host. |
| `--pids-limit` | `256` | Limite de processos simultâneos. Previne fork bomb. |
| `--ulimit nofile` | `1024` | Limite de file descriptors. Previne esgotamento de FDs no host. |
| `--network` | `trabalho_vulnnet` | Rede Docker interna criada com `internal=True`. |

**Retry RW:** Se o container sair imediatamente com código de saída 1, 126 ou 127 (geralmente indica que o entrypoint tentou gravar no FS e falhou), o scanner faz uma segunda tentativa com `read_only=False`. **Todas as outras restrições permanecem** — apenas o FS torna-se gravável.

### 10.2 Isolamento de rede

```
┌─────────────────────────────────────────────────────────────────────┐
│  Rede "trabalho_vulnnet"                                            │
│  Subnet: 172.30.0.0/16                                              │
│  Opções: internal=True, enable_icc=true                             │
│                                                                     │
│   ┌─────────────────────┐    ┌─────────────────────────────────┐   │
│   │ openvas_massscan    │    │ ms_nginx__latest_abc123         │   │
│   │ 172.30.0.2          │───▶│ 172.30.0.x                      │   │
│   │                     │    │ (container sob scan)             │   │
│   │ (também conectado   │    │                                  │   │
│   │  à rede bridge      │    │  SEM GATEWAY                    │   │
│   │  para internet)     │    │  SEM ACESSO EXTERNO              │   │
│   └─────────────────────┘    └─────────────────────────────────┘   │
│                                                                     │
│  internal=True → sem rota padrão → container NÃO pode:             │
│    • Fazer requests HTTP para a internet                            │
│    • Fazer "phone home" / reportar ao C&C                          │
│    • Exfiltrar dados                                                │
│    • Baixar payloads adicionais                                     │
│                                                                     │
│  enable_icc=true → OpenVAS PODE alcançar o container alvo          │
│                                                                     │
│  Sem flag -p → container NÃO é acessível de fora do host           │
└─────────────────────────────────────────────────────────────────────┘
```

**O OpenVAS** é conectado a **duas redes**:
- `bridge` (172.17.0.x): acesso à internet para atualização de feeds NVT
- `trabalho_vulnnet` (172.30.0.2): acesso aos containers alvo para scan

**A API GMP (porta 9390)** é vinculada a `127.0.0.1` apenas — inacessível de qualquer rede Docker ou externa.

### 10.3 Limpeza após scan

O `ContainerManager.lifecycle()` usa `@contextmanager` com bloco `finally` — **garantido executar mesmo em caso de exceção**:

```
finally:
    ├─ container.stop(timeout=10)   # SIGTERM + SIGKILL após timeout
    ├─ container.remove(force=True) # Remove o container e seus layers
    ├─ images.remove(force=True)    # Remove a imagem Docker do disco
    └─ a cada N scans: containers.prune() + images.prune(dangling=True)
```

**Implicação de segurança:** mesmo que o container seja um trojan, worm ou ransomware:
1. Não pode se comunicar com a internet (rede isolada)
2. Não pode modificar o FS do host (sem volumes montados, cap_drop ALL)
3. É destruído após o scan — sem persistência
4. A imagem é removida do disco — sem rastro local

### 10.4 Semáforo GVM

```python
_GVM_SEM = threading.Semaphore(12)  # em worker.py
```

Limita o número de tasks GVM ativas simultaneamente a 12, independente do número de workers. Isso previne que o processo `ospd-openvas` dentro do container OpenVAS seja sobrecarregado com tasks paralelas, o que causa perda do socket IPC interno e crash do daemon.

---

## 11. Referência do Banco de Dados

### 11.1 Schema completo

```sql
CREATE TABLE jobs (
    -- Identificação
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    image        TEXT    NOT NULL UNIQUE,   -- ex: "library/nginx:latest"
    name         TEXT,                       -- slug sanitizado

    -- Estado do job
    status       TEXT    NOT NULL DEFAULT 'pending',
    --   pending  → aguardando ser processado
    --   running  → sendo escaneado (heartbeat atualizado a cada 60s)
    --   done     → scan concluído com sucesso, relatórios salvos
    --   failed   → falha transiente, será re-tentado até max_retries (3)
    --   skipped  → falha permanente, NUNCA re-tentado:
    --              manifest_unknown, exited_startup, no_ip, pull_failed,
    --              image_too_large

    -- Rastreamento de execução
    worker_id    TEXT,           -- "hostname-thread_id" do worker que processou
    container_id TEXT,           -- ID do container Docker (12 chars)
    container_ip TEXT,           -- IP na rede trabalho_vulnnet (ex: "172.30.0.15")
    task_id      TEXT,           -- UUID da task GVM
    target_id    TEXT,           -- UUID do target GVM
    report_id    TEXT,           -- UUID do relatório GVM
    reports_path TEXT,           -- Caminho absoluto do diretório de relatórios

    -- Controle de retry
    attempt      INTEGER NOT NULL DEFAULT 0,       -- Número da tentativa atual
    started_at   TEXT,                             -- ISO8601 UTC
    finished_at  TEXT,                             -- ISO8601 UTC
    heartbeat_at TEXT,           -- Atualizado a cada 60s. Jobs sem heartbeat
                                 -- por > 5 min são automaticamente re-enfileirados.
    error        TEXT,           -- Mensagem de erro (máx 2000 chars)

    -- Resultados de vulnerabilidade
    vuln_critical INTEGER NOT NULL DEFAULT 0,  -- CVSS >= 9.0
    vuln_high     INTEGER NOT NULL DEFAULT 0,  -- CVSS 7.0-8.9
    vuln_medium   INTEGER NOT NULL DEFAULT 0,  -- CVSS 4.0-6.9
    vuln_low      INTEGER NOT NULL DEFAULT 0,  -- CVSS 0.1-3.9
    vuln_log      INTEGER NOT NULL DEFAULT 0,  -- CVSS = 0 (informativo)
    vuln_total    INTEGER NOT NULL DEFAULT 0,  -- Soma de todos os níveis

    -- Metadados
    pull_count    INTEGER NOT NULL DEFAULT 0,  -- pull_count do DockerHub (para priorização)
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
);

-- Índices para performance em grandes datasets (>300k rows)
CREATE INDEX idx_jobs_status     ON jobs(status);
CREATE INDEX idx_jobs_worker     ON jobs(worker_id, status);
CREATE INDEX idx_jobs_pull_count ON jobs(pull_count DESC, status);
```

**Nota:** O banco usa `PRAGMA journal_mode=WAL` e `PRAGMA synchronous=NORMAL` para alta performance com múltiplos writers concorrentes (40 threads). WAL permite reads simultâneos sem bloquear writes.

### 11.2 Migrações automáticas

O `ScanDB` aplica migrações automaticamente na inicialização. Bancos criados antes da adição do campo `vuln_critical` recebem a coluna automaticamente:

```python
_MIGRATIONS = [
    "ALTER TABLE jobs ADD COLUMN vuln_critical INTEGER NOT NULL DEFAULT 0",
]
# Erros OperationalError ("column already exists") são silenciados silenciosamente.
```

### 11.3 Prioridade da fila

Os jobs são processados na seguinte ordem:
1. `pull_count DESC` — imagens mais populares primeiro (mais impacto na supply chain)
2. `id ASC` — desempate pela ordem de inserção (FIFO)
3. `attempt < max_retries` — jobs que esgotaram tentativas não são reprocessados

---

## 12. Referência de Código — Internos

### 12.1 `src/vulnlab/core/container.py` — `ContainerManager`

O componente central de isolamento. Gerencia o ciclo de vida completo de cada container sob scan.

**`ContainerConfig`** (dataclass): todos os parâmetros de segurança e recursos do container. Lida pelo `bin/scanner` a partir de `config.yaml`.

**`lifecycle(image) → @contextmanager`**:
Garante exatamente um `yield` independente de erros no setup. Estrutura:
```
setup phase:  try: pull → run → verify startup → probe TCP
              except Exception: armazena em skip, nunca propaga antes do yield
yield phase:  yield (ip, cid, skip_reason)  # sempre executado uma vez
finally:      stop_rm() + rmi + prune periódico
```

**`probe(ip, timeout)`**: faz tentativas de `socket.create_connection` em todas as portas de `PROBE_PORTS` (HTTP, HTTPS, SSH, MySQL, PostgreSQL, Redis, MongoDB, Elastic, RabbitMQ, Kafka, etc.) a cada 2s até encontrar uma porta aberta. Isso confirma que o serviço está vivo e acessível pelo OpenVAS.

**`_check_size(image)`**: consulta a API de manifesto do registry.docker.io para calcular o tamanho descomprimido da imagem somando o `size` de cada layer, sem fazer pull. Imagens maiores que `max_image_size_mb` são rejeitadas preventivamente.

### 12.2 `src/vulnlab/core/db.py` — `ScanDB`

Fila de trabalho SQLite thread-safe com lock de threading.

**`claim(wid)`**: seleciona o próximo job pendente com maior `pull_count`, atualiza atomicamente para `running` e retorna o dict do job. Thread-safe via `threading.Lock`.

**`reset_stale(mins)`**: re-enfileira jobs em status `running` cujo `heartbeat_at` é anterior a `now - mins`. Chamado uma vez no início de cada sessão do scanner. Garante que containers mortos em runs anteriores não fiquem presos em `running` para sempre.

**`heartbeat(img)`**: chamado a cada 60s por uma thread daemon em background para cada job ativo. Mantém o job "vivo" na visão do `reset_stale`.

### 12.3 `src/vulnlab/scanner/openvas_scanner.py` — `GVMClient`

Cliente GMP (Greenbone Management Protocol) para controle programático do OpenVAS.

**`_get_gmp()`**: context manager que abre uma conexão TLS ao GVM, autentica, e fecha ao sair. Cada chamada de método abre e fecha sua própria conexão — sem estado de conexão compartilhado entre threads.

**`_cache_ids(gmp)`**: na primeira conexão, resolve os nomes de scan_config, port_list e scanner para seus UUIDs internos do GVM. Esses IDs são necessários para criar tasks e são estáveis enquanto o container OpenVAS não for recriado.

**`wait_for_task(task_id, ip, should_stop)`**: polling de status a cada `poll_interval` segundos. Retorna quando o status é `Done`, `Stopped`, ou `Failed`, ou quando `should_stop()` retorna `True` (shutdown signal).

**`get_report_summary(report_id)`**: baixa o XML do relatório e conta resultados por severidade CVSS. Classificação:
- `severity >= 9.0` → `critical`
- `severity >= 7.0` → `high`
- `severity >= 4.0` → `medium`
- `severity >= 0.1` → `low`
- `severity == 0.0` → `log`

**`get_report(report_id, fmt)`**: baixa o relatório no formato especificado (PDF/XML/CSV/TXT) usando os IDs fixos de formato do GVM (`REPORT_FORMAT_IDS`).

### 12.4 `src/vulnlab/scanner/worker.py` — `ScanWorker`

Executa o scan completo de uma imagem. Um `ScanWorker` por thread (via `threading.local`).

**`_GVM_SEM = threading.Semaphore(12)`**: semáforo global que limita tasks GVM ativas. Adquirido antes de `create_target` e liberado após `delete_task`. Independente do número de workers.

**`_hb(img, stop)`**: thread daemon de heartbeat. Chama `db.heartbeat(img)` a cada 60s enquanto o scan está em progresso. Terminada via `threading.Event.set()` no `finally`.

**`_retry(fn, img, step)`**: tenta executar `fn()` até 3 vezes com intervalo de 10s entre tentativas. Usado para `create_target` e `create_task` que podem falhar transitoriamente por sobrecarga do GVM.

### 12.5 `src/vulnlab/core/setup.py` — `EnvironmentSetup`

Provisionamento automático do ambiente na inicialização do scanner.

1. **`_ensure_net()`**: cria a rede `trabalho_vulnnet` com `internal=True` se não existir. Se existir mas não for `internal`, a remove e recria (segurança).
2. **`_ensure_openvas()`**: faz pull da imagem OpenVAS, cria e inicia o container com a porta GMP vinculada a `127.0.0.1:9390`. Conecta o container à rede de scan.
3. **`_wait_gvm(c)`**: aguarda o socket `ospd-openvas.sock` estar disponível dentro do container (verificação via `docker exec`). Mais confiável que só verificar a porta TCP.

### 12.6 `src/vulnlab/discovery/catalog.py` — `ImageSource`

Interface ABC para fontes de imagem. Implementações:

**`DITectorSource`**: lê o JSONL do DITector. Para cada linha, constrói a imagem como `{namespace}/{name}:{tag}`. Tolera linhas malformadas silenciosamente.

**`FileSource`**: lê CSV (detecção automática de cabeçalho `image`) ou TXT (uma imagem por linha). Ignora linhas em branco e comentários (`#`).

### 12.7 `bin/scanner` — `MassScanner`

Orquestrador principal. Loop de controle:

```python
while not shutdown.is_set():
    # Preenche o pool até workers ativos
    while len(active) < workers:
        job = db.claim(worker_id)
        if not job: break
        future = pool.submit(_work, job)
        active[future] = job["image"]
    
    # Coleta resultados de futures concluídos
    for f in [f for f in active if f.done()]:
        _done(f, active.pop(f))
    
    # Se fila vazia e pool vazio, encerra (exceto --watch)
    if not active and db.stats()["pending"] == 0:
        break
    
    time.sleep(2)
```

Thread de progresso (`_prog`): chama `_stats()` a cada 30s para atualizar `scan_status.json`.

---

## 13. Implantação Multi-Máquina

O design do VulnLab assume que **scanner roda em máquina remota** (gpu1) porque o OpenVAS exige 40+ GB de RAM. O banco SQLite é local ao scanner. A máquina de controle (laptop/workstation) só precisa do Python para gerar a lista de imagens via DITector.

### 13.1 Layout recomendado

```
┌──────────────────┐     SSH / SCP      ┌─────────────────────────────┐
│ Máquina Local    │ ──────────────────▶│ gpu1 (scanner remoto)       │
│                  │                    │                             │
│ • DITector       │  Copia:            │ • Docker Engine             │
│   crawl/build/   │  ditector_results  │ • OpenVAS (Docker)          │
│   rank           │  .jsonl            │ • Python + venv             │
│                  │                    │ • LabVulnerabilities/        │
│ Gera:            │                    │   data/mass_scan.db         │
│ ditector_results │                    │   data/reports/             │
│ .jsonl           │                    │                             │
└──────────────────┘                    └─────────────────────────────┘
```

### 13.2 Deploy no gpu1

```bash
# 1. Clonar na máquina remota
ssh gpu1
git clone <repo-url> ~/mass_scanner
cd ~/mass_scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Copiar configuração e lista de imagens da máquina local
# (fazer na máquina LOCAL):
scp config/scanner.yaml gpu1:~/mass_scanner/config/
scp data/ditector_results.jsonl gpu1:~/mass_scanner/data/

# 3. Inicializar OpenVAS (primeira vez — aguarda 20-40 min)
ssh gpu1 "cd ~/mass_scanner && venv/bin/python3 bin/scanner --wait-only -c config/scanner.yaml"

# 4. Seed + scan
ssh gpu1 "cd ~/mass_scanner && nohup venv/bin/python3 bin/scanner \
  --seed --source ditector --file data/ditector_results.jsonl \
  --workers 40 --output data/reports -c config/scanner.yaml -v \
  >> data/reports/logs/run.log 2>&1 &"
```

### 13.3 Monitoramento remoto

```bash
# Status em tempo real
ssh gpu1 "tail -f ~/mass_scanner/data/reports/logs/scanner_*.log"

# Snapshot do progresso
ssh gpu1 "cat ~/mass_scanner/data/reports/scan_status.json"

# Top 10 mais vulneráveis encontrados até agora
ssh gpu1 "sqlite3 ~/mass_scanner/data/mass_scan.db \
  'SELECT image, vuln_critical, vuln_high, vuln_total FROM jobs \
   WHERE status=\"done\" ORDER BY vuln_total DESC LIMIT 10;'"
```

---

## 14. Solução de Problemas

### 14.1 `ospd-openvas` socket perdido / `Connection lost with the scanner`

**Causa:** O processo `ospd-openvas` dentro do container OpenVAS crashou. Acontece quando o scanner é interrompido enquanto tasks GVM estão ativas, causando perda do socket IPC interno do Python multiprocessing manager.

**Sintoma no log:**
```
ERROR | [ERR] nginx:latest: Connection lost with the scanner
ERROR | [ERR] redis:7.0: cannot send data to manager
```

**Solução:**
```bash
# 1. Parar o scanner Python
kill $(pgrep -f "bin/scanner")

# 2. Remover containers de scan órfãos
docker ps -q --filter "name=ms_" | xargs -r docker rm -f

# 3. Reiniciar OpenVAS (~3-5 min para reinicialização)
docker restart openvas_massscan

# 4. Aguardar GVM ficar pronto
docker logs -f openvas_massscan 2>&1 | grep -E "Health|OSPd|VTs were up"

# 5. Retomar scanner (jobs "running" serão automaticamente re-enfileirados)
cd ~/mass_scanner && venv/bin/python3 bin/scanner \
  --workers 40 --output data/reports -c config/scanner.yaml -v &
```

### 14.2 OpenVAS não alcança containers (tasks ficam em `Requested`)

**Causa:** O container OpenVAS não está conectado à rede `trabalho_vulnnet`.

**Diagnóstico:**
```bash
docker inspect openvas_massscan | python3 -c \
  "import json,sys; d=json.load(sys.stdin)[0]
   [print(k, v['IPAddress']) for k,v in d['NetworkSettings']['Networks'].items()]"
```

Saída esperada: duas redes (`bridge` e `trabalho_vulnnet`). Se `trabalho_vulnnet` estiver ausente:

```bash
docker network connect trabalho_vulnnet openvas_massscan

# Verificar conectividade OpenVAS → container alvo
docker exec openvas_massscan curl -s --connect-timeout 3 http://172.30.0.10 | head -5
```

### 14.3 Taxa de skip alta (imagens que "não são serviço")

**Comportamento esperado:** uma fração significativa das imagens públicas no DockerHub não são serviços de rede — são ferramentas CLI, imagens de build, scripts one-shot. Elas saem imediatamente ao iniciar e o scanner as marca como `skipped` (permanente, nunca re-tentado).

Para entender o perfil de skips:
```bash
sqlite3 data/mass_scan.db "
SELECT
  SUBSTR(error, 1, 50) AS motivo,
  COUNT(*) AS n
FROM jobs WHERE status='skipped'
GROUP BY motivo ORDER BY n DESC LIMIT 15;"
```

Motivos comuns:
- `exited:0` — imagem executa um comando e sai (CLI tool, migration script)
- `exited:1` — crash imediato (variável de ambiente obrigatória ausente)
- `pull_failed` — imagem deletada do DockerHub desde o crawl
- `no_ip` — container ficou em estado inconsistente
- `Too large: NNNmb` — imagem maior que `max_image_size_mb`

### 14.4 DockerHub rate limit (429 no pull)

**Sintoma no log:** `Pull failed: 429` ou `toomanyrequests`

**Solução:** Configurar credenciais no `scanner.yaml`:
```yaml
container:
  dockerhub_username: "seu_usuario"
  dockerhub_password: "dckr_pat_xxxxxxxxxxxx"  # Personal Access Token
```

Gere o PAT em: `hub.docker.com → Account Settings → Security → New Access Token`

Com conta autenticada: 200 pulls/6 horas. Sem autenticação: 100 pulls/6 horas por IP.

### 14.5 Redis `vm.overcommit_memory` warning

**Sintoma:** Warning no log do OpenVAS sobre `BGSAVE failed` ou `Background saving disabled`.

**Causa:** Redis usa `fork()` para snapshots. Com `vm.overcommit_memory=0` (padrão Linux), o kernel pode recusar a alocação de memória para o fork mesmo que haja RAM suficiente.

**Solução (no host, requer sudo):**
```bash
# Aplica imediatamente
sudo sysctl -w vm.overcommit_memory=1

# Persiste após reboot
echo 'vm.overcommit_memory = 1' | sudo tee /etc/sysctl.d/99-vulnlab.conf
sudo sysctl -p /etc/sysctl.d/99-vulnlab.conf
```

### 14.6 GVM inicialização lenta (>40 min na primeira execução)

**Normal:** O container `immauss/openvas` na primeira execução baixa e indexa toda a base de dados NVT (Network Vulnerability Tests) do Greenbone. Isso pode levar 20-40 minutos dependendo da velocidade da internet.

**Monitorar progresso:**
```bash
docker logs -f openvas_massscan 2>&1 | grep -E "sync|NVT|VT|feed|percent"
```

Nas inicializações subsequentes (container já existente): ~3-5 minutos.

### 14.7 Disco cheio

```bash
# Ver uso atual
docker system df
df -h /

# Limpeza manual de containers e imagens de scan parados
docker container prune -f
docker image prune -f

# Se `remove_image_after: true` estiver ativo (padrão), isso é feito automaticamente.
# Se o disco encheu mesmo assim, pode haver imagens órfãs:
docker images --filter "dangling=true" -q | xargs -r docker rmi
```

---

## 15. Referências

- **DockerHub Search API:** `https://hub.docker.com/v2/search/repositories`
- **DockerHub Registry API (manifests):** `https://registry-1.docker.io/v2/{repo}/manifests/{tag}`
- **GVM Python Library:** `python-gvm` — `https://python-gvm.readthedocs.io`
- **OpenVAS Docker Image:** `immauss/openvas` — `https://hub.docker.com/r/immauss/openvas`
- **Greenbone Management Protocol (GMP):** versão 26
- **CVSS v3 Scoring Guide:** `https://www.first.org/cvss/v3.1/specification-document`
- **DITector:** Pipeline de crawling e rankeamento de imagens Docker pela criticidade na supply chain
- **SQLite WAL Mode:** `https://www.sqlite.org/wal.html`
