#!/bin/bash
# ============================================================================
# VulnLab Scan Orchestrator - Gerenciador de Scans Sequenciais
#
# Autor: VulnLab Project
# Versão: 1.0.0
#
# Este script gerencia o ciclo de vida dos containers do VulnLab para
# escanear um por vez, economizando recursos de sistema (RAM).
#
# Lógica:
# 1. Obtém a lista de todos os serviços do docker-compose.yml.
# 2. Para cada serviço:
#    a. Inicia o container.
#    b. Aguarda o container ficar pronto.
#    c. Descobre o IP do container.
#    d. Executa o scanner do OpenVAS para esse IP.
#    e. Para o container.
# ============================================================================

set -o pipefail

# Navega para o diretório do script para que os caminhos relativos funcionem
SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCANNER_DIR"

LAB_SCRIPT="../lab.sh"
COMPOSE_FILE="../docker-compose.yml"
STATE_FILE="./scanner_state.json"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# --- Funções Auxiliares ---

log_info() {
    echo -e "${BLUE}INFO: $1${NC}"
}

log_ok() {
    echo -e "${GREEN}OK: $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}WARN: $1${NC}"
}

log_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

# Verifica se os scripts e arquivos necessários existem
check_deps() {
    if [ ! -f "$LAB_SCRIPT" ]; then
        log_error "Script do laboratório ($LAB_SCRIPT) não encontrado."
        exit 1
    fi
    if [ ! -f "$COMPOSE_FILE" ]; then
        log_error "Arquivo Docker Compose ($COMPOSE_FILE) não encontrado."
        exit 1
    fi
    if ! command -v jq &> /dev/null; then
        log_error "'jq' não está instalado. É necessário para ler o arquivo de estado."
        echo "Instale com: sudo apt-get install jq"
        exit 1
    fi
}

# Obtém a lista de serviços do docker-compose, excluindo os de infra (openvas, etc)
get_service_list() {
    docker-compose -f "$COMPOSE_FILE" config --services | grep -v -E 'openvas|prometheus|grafana|zookeeper-old|kafka-old'
}

# Obtém o IP de um container a partir do nome do serviço
get_container_ip() {
    local service_name=$1
    # O docker-compose v1 cria o nome como "trabalho_service_1"
    # Tentamos alguns padrões comuns
    local project_name
    project_name=$(basename "$PWD"/..)
    
    local container_name
    container_name=$(docker-compose -f "$COMPOSE_FILE" ps -q "$service_name")

    if [ -z "$container_name" ]; then
        log_warn "Não foi possível encontrar um container para o serviço '$service_name'. Tentando novamente..."
        sleep 5
        container_name=$(docker-compose -f "$COMPOSE_FILE" ps -q "$service_name")
        if [ -z "$container_name" ]; then
            log_error "Container para o serviço '$service_name' não encontrado após tentativa."
            return 1
        fi
    fi

    docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name"
}

# Verifica no scanner_state.json se um IP já foi escaneado com sucesso
is_scan_completed() {
    local ip_to_check=$1
    if [ ! -f "$STATE_FILE" ]; then
        return 1 # Falso se o arquivo não existe
    fi
    
    local status
    status=$(jq -r ".scans[\"$ip_to_check\"] .status // \"\"" "$STATE_FILE")

    if [[ "$status" == "done" ]]; then
        return 0 # Verdadeiro
    else
        return 1 # Falso
    fi
}

# --- Função Principal ---

main() {
    log_info "Iniciando o Orquestrador de Scan Sequencial"
    check_deps

    # Garante que a rede do lab existe antes de começar
    log_info "Verificando a rede do laboratório..."
    # A primeira chamada a 'start' garantirá que a rede seja criada se não existir
    # docker-compose -f "$COMPOSE_FILE" up --no-start --no-deps

    local services
    services=$(get_service_list)
    local total_services
    total_services=$(echo "$services" | wc -l)
    local current_service_num=0

    log_info "Encontrados $total_services serviços para escanear."

    for service in $services; do
        ((current_service_num++))
        log_info "============================================================="
        log_info "Processando serviço [$current_service_num/$total_services]: $service"
        log_info "============================================================="

        # 1. Inicia o container
        log_info "Subindo o container para o serviço '$service'ப்பான"
        "$LAB_SCRIPT" start "$service" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            log_error "Falha ao iniciar o serviço '$service'. Pulando."
            continue
        fi

        # 2. Aguarda e obtém o IP
        log_info "Aguardando 15s para o container estabilizar..."
        sleep 15
        
        local ip
        ip=$(get_container_ip "$service")
        if [ -z "$ip" ]; then
            log_error "Não foi possível obter o IP para o serviço '$service'. Pulando."
            "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1 # Tenta parar o container
            continue
        fi
        log_ok "Serviço '$service' está rodando no IP: $ip"

        # 3. Verifica se o scan já foi concluído
        if is_scan_completed "$ip"; then
            log_warn "Scan para $service ($ip) já foi concluído anteriormente. Pulando."
        else
            # 4. Executa o scan
            log_info "Iniciando scan para $ip..."
            ./run.sh single "$ip" --config config.yaml -v --service-name "$service"
            if [ $? -ne 0 ]; then
                log_error "O scan para o serviço '$service' ($ip) falhou."
                # Não continuamos, pois pode ser um problema com o OpenVAS
            fi
        fi
        
        # 5. Para o container para liberar recursos
        log_info "Derrubando o container para o serviço '$service'ப்பான"
        "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1
        log_ok "Serviço '$service' parado."
        
        sleep 5 # Pausa entre os serviços
    done

    log_info "============================================================="
    log_info "Orquestração concluída!"
    log_info "Execute './run.sh status' para ver o resumo."
    log_info "============================================================="
}

main "$@"
