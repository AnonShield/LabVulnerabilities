#!/bin/bash
# =============================================================================
# VULNLAB - Laboratório de Aplicações Vulneráveis
# Ambiente para pentest, treinamento em segurança e testes com scanners
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║                    VULNLAB - Vulnerability Lab                         ║"
echo "║          Laboratório de Aplicações Vulneráveis para Pentest            ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect docker compose command
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
elif docker-compose --version &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${RED}[ERRO] Docker Compose não está instalado ou não está no PATH!${NC}"
    exit 1
fi

# Função para mostrar progresso
show_progress() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

# Função para sucesso
show_success() {
    echo -e "${GREEN}[OK] $1${NC}"
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
            SERVICES="$@"
        else
            show_progress "Iniciando todos os containers de forma resiliente..."
            SERVICES=$($COMPOSE_CMD config --services)
        fi
        
        # Certifique-se de que o diretório de logs exista
        mkdir -p logs

        for SERVICE in $SERVICES; do
            echo -e "${YELLOW}--> Iniciando serviço: $SERVICE...${NC}"
            # Tenta iniciar o serviço, redirecionando a saída para /dev/null
            if $COMPOSE_CMD up -d --no-deps $SERVICE &> /dev/null; then
                echo -e "${GREEN}    Serviço $SERVICE iniciado com sucesso.${NC}"
            else
                echo -e "${RED}    ERRO ao iniciar o serviço $SERVICE. Salvando log em logs/$SERVICE.log${NC}"
                # Se falhar, execute novamente para capturar o log de erro
                $COMPOSE_CMD up --no-deps $SERVICE &> logs/$SERVICE.log || true
            fi
        done
        
        show_success "Processo de inicialização concluído!"
        echo ""
        echo -e "${BLUE}Aguarde os serviços iniciarem completamente.${NC}"
        ;;
    
    stop)
        show_progress "Parando todos os containers..."
        $COMPOSE_CMD down
        show_success "Containers parados!"
        ;;
    
    status)
        echo -e "${BLUE}=== STATUS DE TODOS OS CONTAINERS ===${NC}"
        $COMPOSE_CMD ps -a
        echo ""
        echo -e "${BLUE}=== RESUMO ===${NC}"
        # Usar docker diretamente para contagem mais confiável
        RUNNING=$(docker ps -q 2>/dev/null | wc -l)
        TOTAL=$(docker ps -a -q 2>/dev/null | wc -l)
        EXITED=$((TOTAL - RUNNING))
        echo -e "Em execução: ${GREEN}$RUNNING${NC}"
        echo -e "Parados/Com erro: ${RED}$EXITED${NC}"
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
        echo -e "${BLUE}=== IPs DOS CONTAINERS ===${NC}"
        $COMPOSE_CMD ps -q | xargs -I {} docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | sed 's/^\///' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
        ;;
    
    scan-targets)
        echo -e "${BLUE}=== LISTA DE ALVOS PARA OPENVAS ===${NC}"
        echo "Redes: 172.30.0.0/15"
        echo ""
        echo "Ou use os IPs específicos:"
        $COMPOSE_CMD ps -q | xargs -I {} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | grep -v '^$' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
        ;;
    
    export-targets)
        echo -e "${BLUE}Exportando lista de IPs para targets.txt...${NC}"
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
        echo -e "${BLUE}=== ESTATÍSTICAS DE RECURSOS ===${NC}"
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