# OpenVAS Automated Scanner Module

## Visão Geral

Este módulo fornece um conjunto de scripts para automatizar a execução de scans de vulnerabilidade com o OpenVAS (GVM) contra os containers do ambiente VulnLab.

A principal funcionalidade é um orquestrador que gerencia o ciclo de vida dos containers para permitir scans sequenciais, economizando recursos de sistema (CPU e RAM) ao escanear um alvo por vez.

## Componentes

- `openvas_scanner.py`: O script Python principal que se conecta ao GVM, cria e monitora tarefas, e baixa os relatórios.
- `config.yaml`: Arquivo de configuração para o scanner (credenciais, IPs, formatos de relatório).
- `run.sh`: Um wrapper para executar tarefas de scan manualmente (ex: escanear um único IP).
- `setup.sh`: Script para configurar o ambiente, criando um venv Python e instalando as dependências de `requirements.txt`.
- `scan_manager.sh`: O **orquestrador principal**. Este script automatiza o processo de iniciar, escanear e parar cada container do laboratório, um por um.
- `requirements.txt`: Dependências Python.

## Requisitos

- `docker` e `docker-compose`
- `python3` e `python3-venv`
- `jq` (para o orquestrador)

## Instalação

Antes do primeiro uso, execute o script de setup a partir do diretório `scanner/`:

```bash
./bin/setup.sh
```

Isso irá:
1. Criar um ambiente virtual Python (`venv/`).
2. Instalar as dependências necessárias (`gvm-tools`, `PyYAML`).
3. Verificar se o container do OpenVAS está acessível.

## Uso

### Método Recomendado: Scan Orquestrado (Um por Um)

Este método é ideal para máquinas com recursos limitados, pois garante que apenas um container vulnerável esteja rodando a qualquer momento.

Para iniciar o processo completo, execute:

```bash
./bin/scan_manager.sh
```

O script irá:
1. Ler todos os serviços do `docker-compose.yml` principal.
2. Para cada serviço:
   - Iniciar o container e aguardar ficar saudável.
   - Obter seu IP.
   - Chamar o `openvas_scanner.py` para escanear aquele IP.
   - Parar o container.
3. Manter o estado no arquivo `scanner_state.json`. Se o processo for interrompido, ele pode ser reiniciado e continuará de onde parou.

### Método Manual: Scan Direto

O script `run.sh` permite executar scans mais específicos, mas **não gerencia os containers para você**. Você deve iniciá-los manualmente com o `lab.sh`.

**Exemplos:**

```bash
# Escanear um único IP (assumindo que o container já está rodando)
./bin/run.sh single 172.30.9.1

# Escanear um grupo pré-definido de aplicações web
./bin/run.sh webapps

# Ver o status dos scans concluídos
./bin/run.sh status

# Limpar o estado para começar do zero
./bin/run.sh reset
```

## Relatórios

Os relatórios de todos os scans são salvos em `scanner/reports/`. Eles são organizados em subdiretórios nomeados com o IP do alvo.

Exemplo de estrutura:
```
scanner/
└── reports/
    └── 172_30_9_1/
        ├── scan_172_30_9_1_20260125_001530.pdf
        ├── scan_172_30_9_1_20260125_001530.xml
        └── ...
```
