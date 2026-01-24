# VulnLab - Laboratório de Aplicações Vulneráveis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**VulnLab** é um ambiente de laboratório com **115 containers Docker** intencionalmente vulneráveis, projetado para:

- **Testes de Penetração (Pentest)**
- **Treinamento em Segurança da Informação**
- **Estudos de CVEs e vulnerabilidades conhecidas**
- **Testes com scanners de vulnerabilidade** (OpenVAS, Nessus, Qualys, etc.)
- **Prática de CTF (Capture The Flag)**
- **Desenvolvimento de exploits em ambiente controlado**

O ambiente é totalmente automatizado via `docker-compose` e gerenciado por um único script (`lab.sh`).

---

## Categorias de Vulnerabilidades

| Categoria | Exemplos |
|-----------|----------|
| **Web Apps Vulneráveis** | DVWA, Juice Shop, WebGoat, bWAPP, Mutillidae, HackTheBox apps |
| **CVEs Famosas** | Shellshock, Heartbleed, Log4Shell, Spring4Shell, Apache Path Traversal |
| **Serviços Desatualizados** | MySQL 5.5, PostgreSQL 9.3, Redis sem auth, MongoDB sem auth |
| **Metasploitable** | Metasploitable 2 |
| **APIs Vulneráveis** | DVGA (GraphQL), VAmPI |
| **CMS Vulneráveis** | WordPress, Drupal, Joomla |
| **Servidores Web** | Apache 2.2, Nginx 1.10, Tomcat 6/7/8 |
| **DevOps/CI** | GitLab, SonarQube (versões vulneráveis) |
| **Mensageria** | RabbitMQ, Kafka |
| **Monitoramento** | Kibana, Elasticsearch (versões antigas) |

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
