# 🔐 Laboratório de Scan de Vulnerabilidades (VulnLab)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Este projeto, **VulnLab**, oferece um ambiente de laboratório com mais de 200 contêineres Docker intencionalmente vulneráveis, projetado para pesquisa e treinamento em segurança da informação, especialmente para testes com scanners de vulnerabilidade como o OpenVAS.

O ambiente é totalmente automatizado e gerenciado via `docker-compose`, proporcionando uma maneira robusta e modular de implantar um cenário de teste complexo e realista.

---

## 🌟 Visão Geral

- **+200 Aplicações Vulneráveis:** Inclui uma vasta gama de sistemas, desde versões de SO desatualizadas e serviços de rede vulneráveis até aplicações web com falhas conhecidas (OWASP Top 10, CVEs famosas como Shellshock, Heartbleed, etc.).
- **Gerenciamento Simplificado:** Um único script (`lab_full.sh`) controla todo o ciclo de vida do laboratório (`start`, `stop`, `status`, `clean`).
- **Estrutura Modular:** O laboratório é dividido em dois arquivos `docker-compose.yml`, permitindo que você inicie o ambiente base ou o ambiente completo com facilidade.
- **Rede Isolada:** Todos os contêineres operam em uma rede Docker isolada (`172.30.0.0/16` e `172.31.0.0/16`), garantindo que o ambiente de teste não seja exposto externamente.
- **Exportação de Alvos:** Gere facilmente uma lista de todos os IPs dos alvos para importar em seu scanner de vulnerabilidades.

---

## 🚀 Início Rápido

Siga os passos abaixo para ter o laboratório completo em execução.

### 1. Pré-requisitos

- **Sistema Operacional:** Linux (recomendado) ou macOS.
- **Docker e Docker Compose:** Essencial para executar os contêineres. [Instalar Docker](https://get.docker.com/).
- **Git:** Para clonar o repositório.
- **Python 3 e venv:** Para executar scripts de automação.

### 2. Instalação

```bash
# 1. Clone este repositório
git clone https://github.com/CristhianKapelinski/LabVulnerabilities.git
cd LabVulnerabilities

# 2. Crie um ambiente virtual Python e instale as dependências
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Torne o script principal executável
chmod +x lab_full.sh
```

### 3. Gerenciando o Laboratório

O script `lab_full.sh` é a ferramenta central para gerenciar o ambiente.

```bash
# Iniciar todos os 200+ contêineres em background
./lab_full.sh start

# (Opcional) Baixar todas as imagens antes de iniciar
./lab_full.sh pull

# Verificar o status dos contêineres
./lab_full.sh status

# Gerar uma lista de alvos para o seu scanner
./lab_full.sh export-targets
# Isso criará um arquivo 'targets_full.txt' com todos os IPs.

# Parar todos os contêineres
./lab_full.sh stop

# Parar e remover todos os contêineres e volumes
./lab_full.sh clean
```

> **⚠️ AVISO DE SEGURANÇA**
> Este laboratório contém aplicações severamente vulneráveis. **NUNCA** o exponha à internet ou a qualquer rede não confiável. Use-o estritamente em um ambiente de teste isolado.

---

## 📂 Estrutura do Repositório

```
.
├── archive/            # Scripts legados e não utilizados
├── docs/               # Documentação adicional e listas de contêineres
├── scripts/            # Scripts Python para gerar configurações
├── .gitignore          # Arquivos e diretórios ignorados pelo Git
├── docker-compose.yml  # Define o conjunto base de serviços (~100)
├── docker-compose.adicional.yml # Define o conjunto adicional de serviços (~110)
├── inventory.csv       # Inventário de serviços do conjunto base
├── lab.sh              # Script para gerenciar APENAS o conjunto base
├── lab_full.sh         # Script para gerenciar o LABORATÓRIO COMPLETO
├── README.md           # Este arquivo
└── requirements.txt    # Dependências Python
```

---

## 🛠️ Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir uma *issue* ou enviar um *pull request* para sugerir novas aplicações vulneráveis ou melhorias no projeto.

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.