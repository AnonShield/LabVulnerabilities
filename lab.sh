#!/bin/bash
# =============================================================================
# VULNLAB - Laboratório de Aplicações Vulneráveis
# Ambiente para pentest, treinamento em segurança e testes com scanners
#
# Autor: VulnLab Project
# Versão: 2.0.0
# =============================================================================

set -e

# Carrega biblioteca comum
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# Compatibilidade com funções antigas (alias)
show_progress() { log_progress "$1"; }
show_success() { log_success "$1"; }

# Banner
show_banner "VULNLAB - Vulnerability Lab" "Laboratório de Aplicações Vulneráveis para Pentest"

# Detecta o comando docker compose
COMPOSE_CMD=$(detect_compose_cmd) || exit 1

# Configura trap para cleanup em caso de interrupção
setup_traps

# Valida se o docker-compose.yml existe
require_file "${SCRIPT_DIR}/docker-compose.yml" || exit 1

# Função para validar se um serviço existe no compose
validate_service() {
    local service="$1"
    local all_services
    all_services=$($COMPOSE_CMD config --services 2>/dev/null)
    if ! echo "$all_services" | grep -qx "$service"; then
        log_warn "Serviço '$service' não encontrado no docker-compose.yml"
        return 1
    fi
    return 0
}

# Menu principal
case "${1:-}" in
    pull)
        show_progress "Baixando todas as imagens Docker..."
        $COMPOSE_CMD pull --ignore-pull-failures
        show_success "Download concluído!"
        ;;
    
    start)
        # Shift past the 'start' command
        shift

        if [ "$#" -gt 0 ]; then
            show_progress "Iniciando um subconjunto de containers (Smoke Test)..."
            SERVICES=""
            # Valida cada serviço antes de adicionar à lista
            for svc in "$@"; do
                if validate_service "$svc"; then
                    SERVICES="$SERVICES $svc"
                fi
            done
            SERVICES=$(echo "$SERVICES" | xargs)  # Trim whitespace
            if [ -z "$SERVICES" ]; then
                log_error "Nenhum serviço válido especificado."
                exit 1
            fi
        else
            show_progress "Iniciando todos os containers de forma resiliente..."
            SERVICES=$($COMPOSE_CMD config --services)
        fi

        # Certifique-se de que o diretório de logs exista
        ensure_dir logs

        # Contador de sucesso/falha
        SUCCESS_COUNT=0
        FAIL_COUNT=0

        for SERVICE in $SERVICES; do
            echo -e "${COLOR_YELLOW}--> Iniciando serviço: $SERVICE...${COLOR_NC}"
            # Tenta iniciar o serviço, redirecionando a saída para /dev/null
            if $COMPOSE_CMD up -d --no-deps "$SERVICE" &> /dev/null; then
                echo -e "${COLOR_GREEN}    Serviço $SERVICE iniciado com sucesso.${COLOR_NC}"
                ((SUCCESS_COUNT++)) || true
            else
                echo -e "${COLOR_RED}    ERRO ao iniciar o serviço $SERVICE. Salvando log em logs/$SERVICE.log${COLOR_NC}"
                # Se falhar, execute novamente para capturar o log de erro
                $COMPOSE_CMD up --no-deps "$SERVICE" &> "logs/$SERVICE.log" 2>&1 || true
                ((FAIL_COUNT++)) || true
            fi
        done

        show_success "Processo de inicialização concluído!"
        echo ""
        echo -e "Resumo: ${COLOR_GREEN}$SUCCESS_COUNT sucesso${COLOR_NC} | ${COLOR_RED}$FAIL_COUNT falhas${COLOR_NC}"
        echo -e "${COLOR_BLUE}Aguarde os serviços iniciarem completamente.${COLOR_NC}"
        ;;
    
    stop)
        show_progress "Parando todos os containers..."
        $COMPOSE_CMD down
        show_success "Containers parados!"
        ;;
    
    status)
        echo -e "${COLOR_BLUE}=== STATUS DE TODOS OS CONTAINERS ===${COLOR_NC}"
        $COMPOSE_CMD ps -a
        echo ""
        echo -e "${COLOR_BLUE}=== RESUMO ===${COLOR_NC}"
        # Usar docker diretamente para contagem mais confiável
        RUNNING=$(docker ps -q 2>/dev/null | wc -l)
        TOTAL=$(docker ps -a -q 2>/dev/null | wc -l)
        EXITED=$((TOTAL - RUNNING))
        echo -e "Em execução: ${COLOR_GREEN}$RUNNING${COLOR_NC}"
        echo -e "Parados/Com erro: ${COLOR_RED}$EXITED${COLOR_NC}"
        echo -e "Total: $TOTAL"
        ;;
    
    logs)
        if [ -z "${2:-}" ]; then
            echo "Uso: $0 logs <nome-container>"
            exit 1
        fi
        $COMPOSE_CMD logs -f "$2"
        ;;
    
    ips)
        echo -e "${COLOR_BLUE}=== IPs DOS CONTAINERS ===${COLOR_NC}"
        $COMPOSE_CMD ps -q | xargs -I {} docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | sed 's/^\///' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
        ;;
    
    scan-targets)
        echo -e "${COLOR_BLUE}=== LISTA DE ALVOS PARA OPENVAS ===${COLOR_NC}"
        echo "Redes: 172.30.0.0/15"
        echo ""
        echo "Ou use os IPs específicos:"
        $COMPOSE_CMD ps -q | xargs -I {} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | grep -v '^$' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
        ;;
    
    export-targets)
        echo -e "${COLOR_BLUE}Exportando lista de IPs para targets.txt...${COLOR_NC}"
        $COMPOSE_CMD ps -q | xargs -I {} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | grep -v '^$' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > targets.txt
        show_success "Arquivo targets.txt criado com $(wc -l < targets.txt) alvos!"
        ;;
    
    restart)
        show_progress "Reiniciando todos os containers..."
        $COMPOSE_CMD restart
        show_success "Containers reiniciados!"
        ;;
    
    clean)
        show_progress "Parando e removendo containers do compose..."
        $COMPOSE_CMD down -v
        show_progress "Removendo quaisquer containers parados remanescentes..."
        docker container prune -f
        show_success "Limpeza concluída!"
        ;;
    
    stats)
        echo -e "${COLOR_BLUE}=== ESTATÍSTICAS DE RECURSOS ===${COLOR_NC}"
        docker stats --no-stream
        ;;
        
    *)
        echo "Uso: $0 {pull|start|stop|status|logs|ips|scan-targets|export-targets|restart|clean|stats}"
        echo "Para smoke test: $0 start <serviço1> <serviço2> ..."
        echo ""
        echo "Comandos:"
        echo "  pull          - Baixar todas as imagens Docker"
        echo "  start         - Iniciar todos os containers (ou um subconjunto)"
        echo "  stop          - Parar todos os containers"
        echo "  status        - Ver status dos containers"
        echo "  logs <nome>   - Ver logs de um container específico"
        echo "  ips           - Listar IPs de todos os containers"
        echo "  scan-targets  - Mostrar lista de alvos para scan"
        echo "  export-targets- Exportar IPs para arquivo targets.txt"
        echo "  restart       - Reiniciar todos os containers"
        echo "  clean         - Remover containers e volumes"
        echo "  stats         - Ver uso de recursos"
        exit 1
        ;;
esac