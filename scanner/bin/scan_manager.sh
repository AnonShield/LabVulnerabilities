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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCANNER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$SCANNER_DIR"

# Carrega biblioteca comum
source "${PROJECT_ROOT}/lib/common.sh"

# Configura traps para cleanup
setup_traps

# Garante que todos os containers sejam parados na saída
cleanup_containers() {
    log_info "Parando todos os containers do laboratório como parte do cleanup..."
    # O timeout previne que o script de cleanup trave
    timeout 60s "$LAB_SCRIPT" stop >/dev/null 2>&1
    log_ok "Cleanup de containers concluído."
}
register_cleanup cleanup_containers


LAB_SCRIPT="${PROJECT_ROOT}/lab.sh"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
STATE_FILE="${SCANNER_DIR}/scanner_state.json"

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

# ============================================================================
# FUNÇÕES DE VERIFICAÇÃO RÁPIDA (PRÉ-SCAN)
# ============================================================================

# Extrai o IP esperado de um serviço do docker-compose.yml SEM iniciar o container
# Isso permite verificar se já foi escaneado ANTES de gastar tempo iniciando
get_expected_ip() {
    local service_name=$1

    # Usa docker-compose config para obter a configuração expandida
    # e extrai o ipv4_address do serviço específico
    local ip
    ip=$(docker-compose -f "$COMPOSE_FILE" config 2>/dev/null | \
         awk -v svc="$service_name" '
         /^  [a-zA-Z0-9_-]+:$/ { current_service = substr($1, 1, length($1)-1) }
         current_service == svc && /ipv4_address:/ { print $2; exit }
         ')

    # Se não encontrou com awk, tenta com grep (fallback)
    if [ -z "$ip" ]; then
        ip=$(docker-compose -f "$COMPOSE_FILE" config 2>/dev/null | \
             grep -A 20 "^  ${service_name}:" | \
             grep "ipv4_address:" | \
             head -1 | \
             awk '{print $2}')
    fi

    echo "$ip"
}

# Cache de IPs para evitar múltiplas chamadas ao docker-compose config
declare -A IP_CACHE

# Carrega todos os IPs de uma vez (mais eficiente)
load_all_expected_ips() {
    log_info "Carregando mapeamento de serviços para IPs..."

    local config_output
    config_output=$(docker-compose -f "$COMPOSE_FILE" config 2>/dev/null)

    local current_service=""
    while IFS= read -r line; do
        # Detecta início de serviço (formato: "  service_name:")
        if [[ "$line" =~ ^[[:space:]]{2}([a-zA-Z0-9_-]+):$ ]]; then
            current_service="${BASH_REMATCH[1]}"
        fi
        # Detecta ipv4_address dentro do serviço atual
        if [[ -n "$current_service" && "$line" =~ ipv4_address:[[:space:]]*([0-9.]+) ]]; then
            IP_CACHE["$current_service"]="${BASH_REMATCH[1]}"
        fi
    done <<< "$config_output"

    log_info "Carregados ${#IP_CACHE[@]} mapeamentos de IP."
}

# Obtém IP do cache (rápido) ou calcula (fallback)
get_expected_ip_cached() {
    local service_name=$1

    if [[ -n "${IP_CACHE[$service_name]:-}" ]]; then
        echo "${IP_CACHE[$service_name]}"
    else
        get_expected_ip "$service_name"
    fi
}

# Obtém a lista de serviços do docker-compose, excluindo os de infra (openvas, etc)
get_service_list() {
    if [ -n "$SERVICE_FILTER_LIST" ]; then
        # Retorna apenas os serviços na lista de filtro
        # Usamos tr para converter a string em lista de serviços separados por newline
        echo "$SERVICE_FILTER_LIST" | tr ' ' '\n'
    else
        # Comportamento padrão: todos os serviços exceto infra
        docker-compose -f "$COMPOSE_FILE" config --services | grep -v -E 'openvas|prometheus|grafana|zookeeper-old|kafka-old'
    fi
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

# ============================================================================
# FUNÇÕES DE ORQUESTRAÇÃO
# ============================================================================

# Aguarda um container ficar saudável
wait_container_healthy() {
    local service=$1
    local max_wait=${2:-120}
    local wait_time=0
    local container_id

    container_id=$(docker-compose -f "$COMPOSE_FILE" ps -q "$service")
    if [ -z "$container_id" ]; then
        return 1
    fi

    while [ $wait_time -lt $max_wait ]; do
        local health_status
        health_status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$container_id" 2>/dev/null)

        if [ "$health_status" == "healthy" ]; then
            log_ok "Container está saudável!"
            return 0
        fi

        # Se não há healthcheck, consideramos pronto após 20s
        if [ "$health_status" == "no-healthcheck" ]; then
            log_warn "Serviço '$service' não possui health check. Aguardando 20s."
            sleep 20
            return 0
        fi

        sleep 5
        wait_time=$((wait_time + 5))
        echo -n "."
    done

    echo "" # Nova linha
    return 1
}

# Orquestração sequencial (comportamento padrão, agora com verificação rápida)
sequential_orchestrate() {
    local services=$1
    local total_services
    total_services=$(echo "$services" | wc -w)
    local current_service_num=0
    local skipped_count=0
    local scanned_count=0

    for service in $services; do
        ((current_service_num++))

        # ================================================================
        # VERIFICAÇÃO RÁPIDA (ANTES de iniciar o container!)
        # Pula se --force não foi usado
        # ================================================================
        local expected_ip
        expected_ip=$(get_expected_ip_cached "$service")

        if [ "$FORCE_RESCAN" != "true" ] && [ -n "$expected_ip" ] && is_scan_completed "$expected_ip"; then
            log_info "[$current_service_num/$total_services] Pulando '$service' ($expected_ip) - já escaneado"
            ((skipped_count++))
            continue
        fi

        # ================================================================
        # PROCESSAMENTO DO CONTAINER (só se não foi escaneado)
        # ================================================================
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
        if ! wait_container_healthy "$service" 120; then
            log_error "Timeout: O container para o serviço '$service' não ficou saudável. Pulando."
            "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1
            continue
        fi
        echo "" # Nova linha após os pontos de espera

        # 3. Obtém o IP real do container
        local ip
        ip=$(get_container_ip "$service")
        if [ -z "$ip" ]; then
            log_error "Não foi possível obter o IP para o serviço '$service'. Pulando."
            "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1
            continue
        fi
        log_ok "Serviço '$service' está rodando no IP: $ip"

        # 4. Executa o scan
        log_info "Iniciando scan para $ip..."
        local extra_args=("--config" "${SCANNER_DIR}/config.yaml" "-v" "--service-name" "$service")
        if [ "$FORCE_RESCAN" = "true" ]; then
            extra_args+=("--force")
        fi
        "${SCRIPT_DIR}/run.sh" single "$ip" "${extra_args[@]}"
        if [ $? -ne 0 ]; then
            log_error "O scan para o serviço '$service' ($ip) falhou."
        else
            ((scanned_count++))
        fi

        # 5. Para o container para liberar recursos
        log_info "Derrubando o container para o serviço '$service'..."
        "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1
        log_ok "Serviço '$service' parado."

        sleep 5 # Pausa entre os serviços
    done

    log_info "============================================================="
    log_info "Resumo: Escaneados=$scanned_count, Pulados (já feitos)=$skipped_count"
    log_info "============================================================="
}

# Orquestração paralela (múltiplos containers/scans simultâneos)
run_parallel_orchestration() {
    local services=$1
    local container_batch_size=${CONTAINER_CONCURRENCY:-4}
    local scan_mode=${GVM_SCAN_MODE:-"parallel"}

    # Converte para array (serviços vêm separados por newline)
    local -a services_array=()
    while IFS= read -r svc; do
        [[ -n "$svc" ]] && services_array+=("$svc")
    done <<< "$services"
    local total=${#services_array[@]}

    # Filtra serviços não escaneados
    local -a pending_services=()
    log_info "Filtrando serviços já escaneados..."
    for service in "${services_array[@]}"; do
        local expected_ip
        expected_ip=$(get_expected_ip_cached "$service")

        if [ -z "$expected_ip" ]; then
            log_warn "Não foi possível determinar IP para '$service'. Incluindo na lista."
            pending_services+=("$service")
        elif [ "$FORCE_RESCAN" != "true" ] && is_scan_completed "$expected_ip"; then
            log_debug "Pulando '$service' ($expected_ip) - já escaneado"
        else
            pending_services+=("$service")
        fi
    done

    local pending_count=${#pending_services[@]}
    log_info "Serviços pendentes para scan: $pending_count de $total"

    if [ $pending_count -eq 0 ]; then
        log_info "Nenhum serviço novo para escanear."
        return 0
    fi

    # Processa em lotes de containers
    for ((i=0; i<pending_count; i+=container_batch_size)); do
        local batch_services=("${pending_services[@]:i:container_batch_size}")
        local batch_ips=()
        local batch_num=$((i / container_batch_size + 1))
        local total_batches=$(( (pending_count + container_batch_size - 1) / container_batch_size ))

        log_info "============================================================="
        log_info "Processando lote de containers [$batch_num/$total_batches]: ${#batch_services[@]} serviços"
        log_info "============================================================="

        # 1. Inicia todos os containers do lote em paralelo
        log_info "Iniciando ${#batch_services[@]} containers em paralelo..."
        for service in "${batch_services[@]}"; do
            "$LAB_SCRIPT" start "$service" >/dev/null 2>&1 &
        done
        wait
        log_ok "Comando de início enviado para todos os containers do lote."

        # 2. Aguarda todos ficarem saudáveis e coleta IPs
        log_info "Aguardando containers ficarem prontos..."
        sleep 15 # Dá um tempo inicial para estabilização

        for service in "${batch_services[@]}"; do
            local ip
            ip=$(get_container_ip "$service")
            if [ -n "$ip" ]; then
                batch_ips+=("$ip")
                log_info "  [PRONTO] $service -> $ip"
            else
                log_warn "  [FALHA] $service -> IP não encontrado após início"
            fi
        done

        if [ ${#batch_ips[@]} -eq 0 ]; then
            log_error "Nenhum IP válido no lote. Pulando para o próximo."
            # Para containers deste lote para não deixá-los rodando
            for service in "${batch_services[@]}"; do
                "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1 &
            done
            wait
            continue
        fi

        # 3. Executa scan
        log_info "Executando scan GVM em modo '$scan_mode' para ${#batch_ips[@]} IPs..."
        local extra_args=("--config" "${SCANNER_DIR}/config.yaml" "-v")
        if [ "$FORCE_RESCAN" = "true" ]; then
            extra_args+=("--force")
        fi

        if [ "$scan_mode" = "parallel" ]; then
            extra_args+=("--max-concurrent" "$GVM_CONCURRENCY")
        else # batch
            extra_args+=("--batch-size" "$GVM_BATCH_SIZE")
        fi

        "${SCRIPT_DIR}/run.sh" "$scan_mode" "${batch_ips[@]}" "${extra_args[@]}"
        local exit_code=$?
        log_debug "O script 'run.sh' terminou com o código de saída: $exit_code"

        if [ $exit_code -eq 130 ]; then
            log_warn "Interrupção detectada. Finalizando orquestrador."
            exit 130
        fi

        # 4. Para todos os containers do lote (a função de cleanup geral vai pegar na saída)
        log_info "Parando containers do lote..."
        for service in "${batch_services[@]}"; do
            "$LAB_SCRIPT" stop "$service" >/dev/null 2>&1 &
        done
        wait
        log_ok "Lote de containers [$batch_num/$total_batches] concluído."

        sleep 5
    done

    log_info "============================================================="
    log_info "Orquestração paralela concluída!"
    log_info "============================================================="
}

# --- Função Principal ---

show_usage() {
    echo "Uso: $0 [opções]"
    echo ""
    echo "Opções de Orquestração de Containers:"
    echo "  --sequential         Executa um container por vez (padrão)."
    echo "  --parallel [N]       Executa N containers em paralelo (padrão: 4)."
    echo ""
    echo "Opções de Scan do OpenVAS (GVM):"
    echo "  --scan-mode [MODE]   Modo de scan: 'parallel' ou 'batch' (padrão: parallel)."
    echo "  --gvm-concurrency N  N tasks GVM simultâneas (para --scan-mode parallel, padrão: 4)."
    echo "  --gvm-batch-size N   N IPs por task GVM (para --scan-mode batch, padrão: 10)."
    echo ""
    echo "Opções de Seleção de Serviços:"
    echo "  --services [SRV...]  Escaneia apenas os serviços especificados (ex: dvwa juice-shop)."
    echo ""
    echo "Outras Opções:"
    echo "  --force              Re-escaneia todos os serviços, mesmo os já concluídos."
    echo "  --dry-run            Apenas lista os serviços que seriam escaneados."
    echo "  -h, --help           Mostra esta ajuda."
    echo ""
    echo "Exemplos:"
    echo "  ./scan_manager.sh --services dvwa --sequential               # Escaneia dvwa sequencialmente"
    echo "  ./scan_manager.sh --services dvwa juice-shop --parallel 2    # Escaneia dvwa e juice-shop em paralelo"
    echo "  ./scan_manager.sh --parallel 20                                  # 20 containers, 20 scans GVM paralelos"
    echo "  ./scan_manager.sh --parallel 20 --scan-mode batch --gvm-batch-size 5  # 20 containers, scans GVM em lotes de 5"
    echo "  ./scan_manager.sh --force --sequential                         # Re-escaneia tudo, 1 por 1"
}

main() {
    # Defaults
    local orchestration_mode="sequential"
    local container_concurrency=1
    local gvm_scan_mode="parallel"
                local gvm_concurrency=4
                local gvm_batch_size=10
                local dry_run=false
                local force_rescan=false
                local service_filter_list="" # Lista de serviços a serem escaneados
    
                # Análise de argumentos aprimorada
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        --sequential)
                            orchestration_mode="sequential"
                            container_concurrency=1
                            shift
                            ;;
                        --parallel)
                            orchestration_mode="parallel"
                            if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                                container_concurrency=$2
                                gvm_concurrency=$2 # Padrão sensato: concorrência GVM acompanha a de containers
                                shift 2
                            else
                                container_concurrency=4
                                gvm_concurrency=4
                                shift
                            fi
                            ;;
                        --scan-mode)
                            gvm_scan_mode=$2
                            shift 2
                            ;;
                        --gvm-concurrency)
                            gvm_concurrency=$2
                            shift 2
                            ;;
                        --gvm-batch-size)
                            gvm_batch_size=$2
                            shift 2
                            ;;
                        --batch) # Manter para compatibilidade, mas agora só afeta o modo GVM
                            gvm_scan_mode="batch"
                            if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                                gvm_batch_size=$2
                                shift
                            fi
                            shift
                            ;;
                        --services)
                            shift
                            # Coleta todos os argumentos até a próxima flag ou fim
                            while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                                service_filter_list+="$1 "
                                shift
                            done
                            ;;
                        --force)
                            force_rescan=true
                            shift
                            ;;
                        --dry-run)
                            dry_run=true
                            shift
                            ;;
                        -h|--help)
                            show_usage
                            exit 0
                            ;;
                        *)
                            log_error "Opção desconhecida: $1"
                            show_usage
                            exit 1
                            ;;
                    esac
                done
    
                # Exporta variáveis para serem usadas pelas funções de orquestração
                export CONTAINER_CONCURRENCY=$container_concurrency
                export GVM_SCAN_MODE=$gvm_scan_mode
                export GVM_CONCURRENCY=$gvm_concurrency
                export GVM_BATCH_SIZE=$gvm_batch_size
                export FORCE_RESCAN=$force_rescan
                export SERVICE_FILTER_LIST="$service_filter_list" # Exporta a lista de serviços filtrados
    log_info "============================================================="
    log_info "VulnLab Scan Orchestrator"
    log_info "  Orquestração de Contêineres: $orchestration_mode ($container_concurrency containers)"
    log_info "  Modo de Scan (GVM):          $gvm_scan_mode"
    if [ "$gvm_scan_mode" = "parallel" ]; then
        log_info "  - Concorrência GVM:          $gvm_concurrency"
    else
        log_info "  - Tamanho do Lote GVM:       $gvm_batch_size"
    fi
    log_info "============================================================="
    if [ "$force_rescan" = true ]; then
        log_warn "MODO FORCE: Re-escaneando todos os serviços"
        log_info "============================================================="
    fi

    check_deps

    # Carrega mapeamento de IPs (mais rápido que consultar um por um)
    load_all_expected_ips

    local services
    services=$(get_service_list)
    local total_services
    total_services=$(echo "$services" | wc -w)

    log_info "Encontrados $total_services serviços para processar."

    # Modo dry-run: apenas lista o que seria feito
    if [ "$dry_run" = true ]; then
        log_info "Modo dry-run - listando serviços:"
        local pending=0
        local done=0
        local to_scan=0
        for service in $services; do
            local expected_ip
            expected_ip=$(get_expected_ip_cached "$service")
            if [ -n "$expected_ip" ] && is_scan_completed "$expected_ip"; then
                if [ "$force_rescan" = true ]; then
                    echo -e "  ${COLOR_MAGENTA}[RESCAN]${COLOR_NC} $service ($expected_ip)"
                    ((to_scan++))
                else
                    echo -e "  ${COLOR_GREEN}[DONE]${COLOR_NC} $service ($expected_ip)"
                fi
                ((done++))
            else
                echo -e "  ${COLOR_YELLOW}[PENDING]${COLOR_NC} $service ($expected_ip)"
                ((pending++))
                ((to_scan++))
            fi
        done
        if [ "$force_rescan" = true ]; then
            log_info "Resumo: $done já escaneados + $pending pendentes = $to_scan para re-escanear (--force)"
        else
            log_info "Resumo: $done já escaneados, $pending pendentes"
        fi
        exit 0
    fi

    # Executa orquestração
    case "$orchestration_mode" in
        sequential)
            sequential_orchestrate "$services"
            ;;
        parallel)
            run_parallel_orchestration "$services"
            ;;
    esac

    log_info "============================================================="
    log_info "Orquestração concluída!"
    log_info "Execute './run.sh status' para ver o resumo."
    log_info "============================================================="
}

main "$@"
