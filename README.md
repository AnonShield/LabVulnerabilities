# VulnLab - Laboratório de Aplicações Vulneráveis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**VulnLab** é um ambiente de laboratório com **144 containers Docker** intencionalmente vulneráveis, projetado para:

- **Testes de Penetração (Pentest)**
- **Treinamento em Segurança da Informação**
- **Estudos de CVEs e vulnerabilidades conhecidas**
- **Testes com scanners de vulnerabilidade** (OpenVAS, Nessus, Qualys, etc.)
- **Prática de CTF (Capture The Flag)**
- **Desenvolvimento de exploits em ambiente controlado**

O ambiente é totalmente automatizado via `docker-compose` e gerenciado por um único script (`lab.sh`).

---

## Categorias de Vulnerabilidades

O laboratório conta com **144 containers Docker** intencionalmente vulneráveis, distribuídos em diversas categorias para abranger um amplo espectro de cenários de ataque e defesa.

| Categoria                                                  | Quantidade de Tipos Distintos | Exemplos Específicos (Nomes de Serviços ou Imagens no `docker-compose.yml`) |
| :------------------------------------------------------ | :---------------------------: | :------------------------------------------------------------------------- |
| **Aplicações Web Vulneráveis**                          |              23               | `metasploitable2` (inclui vários webapps e serviços), `juice-shop`, `hackazon`, `webgoat`, `railsgoat`, `security-shepherd`, `dvwa`, `bwapp`, `mutillidae`, `vampi`, `damn-vulnerable-graphql` (DVGA), `wackopicko`, `dvna`, `ssrflab`, `sqli`, `httpbin`, `echo-server` |
| **CMS e Plataformas**                                   |               6               | `wordpress-vuln`, `wp46`, `wp49`, `drupal7`, `drupal85`, `joomla38`, `owncloud-old`, `owncloud9`, `nextcloud12`, `mediawiki-old`, `mediawiki128`, `redmine33` |
| **Serviços de Banco de Dados Desatualizados/Vulneráveis** |               6               | `mysql-old`, `mysql55`, `mysql56`, `postgres-old`, `pg93`, `pg95`, `mongodb-noauth`, `mongo32`, `mongo36`, `redis-noauth`, `redis32`, `redis50`, `cassandra22`, `couchdb-old`, `couchdb16` |
| **Servidores Web e de Aplicação Desatualizados/Vulneráveis** |               7               | `apache-cve-2021-41773`, `apache-old`, `apache22`, `apache246`, `nginx-old`, `nginx110`, `nginx112`, `nginx114`, `lighttpd`, `tomcat7-vuln`, `tomcat-ghostcat`, `tomcat6`, `tomcat7`, `tomcat8`, `jboss7`, `wildfly9`, `wildfly10` |
| **Ferramentas DevOps e CI/CD Desatualizadas/Vulneráveis** |               7               | `gitlab-vuln`, `gitlab10`, `jenkins260`, `jenkins2150`, `nexus2`, `sonar67`, `sonar70`, `artifactory5`, `gogs011`, `gitea14` |
| **Serviços de Mensageria e Stream**                     |               3               | `rabbitmq-old`, `rabbit36`, `rabbit37`, `kafka-old`, `kafka011`, `activemq-old`, `activemq514` |
| **Serviços de Monitoramento e Log**                     |               7               | `elasticsearch-old`, `es24`, `es56`, `kibana-old`, `kibana46`, `kibana56`, `logstash56`, `grafana-old`, `prometheus-old`, `influx13`, `nagios`, `zabbix40` |
| **Serviços de Rede e Infraestrutura**                   |              19               | `proftpd-vuln`, `ssh-cve-2016-6515`, `ubuntu-ssh-old`, `openssh`, `sambacry`, `dns-vuln`, `bind`, `mailcatcher`, `squid-old`, `squid35`, `docker-registry-noauth`, `asterisk`, `openldap`, `phpldapadmin`, `snmpd`, `haproxy15`, `haproxy16`, `haproxy17`, `traefik15`, `dovecot`, `vsftpd`, `memcached-old`, `memcached14`, `memcached15` |
| **Linguagens e Runtimes Desatualizados**                |               6               | `python27`, `python35`, `python36`, `node6`, `node8`, `node10`, `ruby23`, `ruby24`, `php56`, `php70`, `go19`, `express-old` |
| **Sistemas Operacionais Desatualizados**                |               8               | `ubuntu14`, `ubuntu16`, `debian8`, `debian9`, `centos6`, `centos7`, `alpine37`, `fedora28` | |

---

## Início Rápido

### Pré-requisitos

- **Docker** e **Docker Compose** instalados
- **8GB+ RAM** recomendado (para rodar múltiplos containers)
- **50GB+ disco** (para as imagens Docker)

### Instalação

```bash
# Clone o repositório
git clone https://github.com/CristhianKapelinski/VulnLab.git
cd VulnLab

# Torne o script executável
chmod +x lab.sh
```

### Uso Básico

```bash
# Iniciar todos os containers
./lab.sh start

# Verificar status
./lab.sh status

# Listar IPs dos containers
./lab.sh ips

# Exportar lista de alvos para scanner
./lab.sh export-targets

# Parar containers
./lab.sh stop

# Limpar tudo (containers + volumes)
./lab.sh clean
```

### Smoke Test (iniciar apenas alguns containers)

```bash
# Iniciar apenas containers específicos para teste rápido
./lab.sh start dvwa juice-shop metasploitable2 webgoat
```

---

## Comandos Disponíveis

| Comando | Descrição |
|---------|-----------|
| `./lab.sh start` | Inicia todos os containers de forma resiliente |
| `./lab.sh start <srv1> <srv2>` | Inicia apenas os containers especificados |
| `./lab.sh stop` | Para todos os containers |
| `./lab.sh status` | Mostra status de todos os containers |
| `./lab.sh logs <container>` | Mostra logs de um container específico |
| `./lab.sh ips` | Lista IPs de todos os containers |
| `./lab.sh scan-targets` | Mostra alvos para scanners |
| `./lab.sh export-targets` | Exporta IPs para `targets.txt` |
| `./lab.sh restart` | Reinicia todos os containers |
| `./lab.sh clean` | Remove containers e volumes |
| `./lab.sh stats` | Mostra uso de recursos (CPU/RAM) |
| `./lab.sh pull` | Baixa todas as imagens previamente |

---

## Rede

Todos os containers operam em uma rede Docker isolada:

- **Subnet:** `172.30.0.0/15`
- **Nome da rede:** `vulnnet`

---

## Estrutura do Repositório

```
.
├── docker-compose.yml  # Definição de todos os serviços
├── lab.sh              # Script principal de gerenciamento
├── inventory.csv       # Inventário de serviços
├── logs/               # Logs de containers com erro
├── scripts/            # Scripts auxiliares
└── README.md           # Este arquivo
```

---

## Aviso de Segurança

> **NUNCA** exponha este laboratório à internet ou a redes não confiáveis.
>
> Este ambiente contém aplicações **severamente vulneráveis** e deve ser usado **apenas** em ambientes isolados para fins de estudo e pesquisa.

---

## Contribuições

Contribuições são bem-vindas! Abra uma issue ou envie um pull request para:
- Adicionar novas aplicações vulneráveis
- Corrigir problemas de configuração
- Melhorar a documentação

---

## Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
