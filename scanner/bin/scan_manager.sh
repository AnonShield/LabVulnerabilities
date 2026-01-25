#!/bin/bash
# ============================================================================
# VulnLab Scan Orchestrator - Gerenciador de Scans Sequenciais
#
# Autor: VulnLab Project
# Versão: 1.1.0
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

# Carrega biblioteca comum
source "${SCANNER_DIR}/../lib/common.sh"

# Configura traps para cleanup
setup_traps

LAB_SCRIPT="../lab.sh"
COMPOSE_FILE="../docker-compose.yml"
STATE_FILE="./scanner_state.json"

# Alias para compatibilidade
log_ok() { log_success "$1"; }

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
        log_info "Subindo o container para o serviço '$service'..."
        "$LAB_SCRIPT" start "$service" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            log_error "Falha ao iniciar o serviço '$service'. Pulando."
            continue
        fi

        # 2. Aguarda o container ficar saudável
        log_info "Aguardando o container ficar saudável..."
        local wait_time=0
        local max_wait=120 # Timeout de 2 minutos
        local container_id
        container_id=$(docker-compose -f "$COMPOSE_FILE" ps -q "$service")

        while [ $wait_time -lt $max_wait ]; do
            local health_status
            health_status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$container_id")
            
            if [ "$health_status" == "healthy" ]; then
                log_ok "Container está saudável!"
                break
            fi
            
            # Se não há healthcheck, consideramos pronto após 20s
            if [ "$health_status" == "no-healthcheck" ]; then
                log_warn "Serviço '$service' não possui health check. Aguardando 20s."
                sleep 20
                break
            fi

            sleep 5
            wait_time=$((wait_time + 5))
            echo -n "."
        done
        echo "" # Nova linha após os pontos de espera

        if [ $wait_time -ge $max_wait ]; then
            log_error "Timeout: O container para o serviço '$service' não ficou saudável em $max_wait segundos. Pulando."
            "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1
            continue
        fi

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
        log_info "Derrubando o container para o serviço '$service'..."
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
