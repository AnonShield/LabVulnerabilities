#!/bin/bash
# =============================================================================
# VULNERABILITY LAB SETUP SCRIPT - FULL VERSION
# Para paper SBRC - Scan com OpenVAS
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

COMPOSE_FILES="-f docker-compose.yml -f docker-compose.adicional.yml"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║           VULNERABILITY SCAN LAB - SETUP SCRIPT (FULL)                ║"
echo "║           200+ Aplicações Vulneráveis para OpenVAS                     ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar se Docker está instalado
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERRO] Docker não está instalado!${NC}"
    echo "Instale com: curl -fsSL https://get.docker.com | sh"
    exit 1
fi

# Verificar se Docker Compose está disponível
if ! docker compose version &> /dev/null; then
    echo -e "${RED}[ERRO] Docker Compose não está disponível!${NC}"
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
        show_progress "Baixando todas as imagens Docker (base + adicional)..."
        docker compose $COMPOSE_FILES pull --ignore-pull-failures
        show_success "Download concluído!"
        ;;
    
    start)
        show_progress "Iniciando todos os containers (base + adicional)..."
        docker compose $COMPOSE_FILES up -d
        show_success "Containers iniciados!"
        echo ""
        echo -e "${BLUE}Aguarde ~5-10 minutos para todos os serviços iniciarem.${NC}"
        echo -e "${BLUE}Redes do lab: 172.30.0.0/16 e 172.31.0.0/16${NC}"
        ;;
    
    stop)
        show_progress "Parando todos os containers..."
        docker compose $COMPOSE_FILES down
        show_success "Containers parados!"
        ;;
    
    status)
        echo -e "${BLUE}=== STATUS DOS CONTAINERS ===${NC}"
        docker compose $COMPOSE_FILES ps
        echo ""
        echo -e "${BLUE}=== TOTAL DE CONTAINERS ===${NC}"
        RUNNING=$(docker compose $COMPOSE_FILES ps --status running -q | wc -l)
        TOTAL=$(docker compose $COMPOSE_FILES ps -a -q | wc -l)
        echo -e "Running: ${GREEN}$RUNNING${NC} / Total: $TOTAL"
        ;;
    
    logs)
        if [ -z "${2:-}" ]; then
            echo "Uso: $0 logs <nome-container>"
            exit 1
        fi
        docker compose $COMPOSE_FILES logs -f "$2"
        ;;
    
    ips)
        echo -e "${BLUE}=== IPs DOS CONTAINERS ===${NC}"
        docker compose $COMPOSE_FILES ps -q | xargs -I {} docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | sed 's/^\///' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
        ;;
    
    scan-targets)
        echo -e "${BLUE}=== LISTA DE ALVOS PARA OPENVAS ===${NC}"
        echo "Redes: 172.30.0.0/16, 172.31.0.0/16"
        echo ""
        echo "Ou use os IPs específicos:"
        docker compose $COMPOSE_FILES ps -q | xargs -I {} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | grep -v '^$' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
        ;;
    
    export-targets)
        echo -e "${BLUE}Exportando lista de IPs para targets_full.txt...${NC}"
        docker compose $COMPOSE_FILES ps -q | xargs -I {} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | grep -v '^$' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > targets_full.txt
        show_success "Arquivo targets_full.txt criado com $(wc -l < targets_full.txt) alvos!"
        ;;
    
    restart)
        show_progress "Reiniciando todos os containers..."
        docker compose $COMPOSE_FILES restart
        show_success "Containers reiniciados!"
        ;;
    
    clean)
        show_progress "Removendo containers e volumes..."
        docker compose $COMPOSE_FILES down -v
        show_success "Limpeza concluída!"
        ;;
    
    *)
        echo "Uso: $0 {pull|start|stop|status|logs|ips|scan-targets|export-targets|restart|clean}"
        exit 1
        ;;
esac
 down -v --remove-orphans
        show_success "Limpeza concluída!"
        ;;
    
    stats)
        echo -e "${BLUE}=== ESTATÍSTICAS DE RECURSOS ===${NC}"
        docker stats --no-stream
        ;;
    
    *)
        echo "Uso: $0 {pull|start|stop|status|logs|ips|scan-targets|export-targets|restart|clean|stats}"
        echo ""
        echo "Comandos:"
        echo "  pull          - Baixar todas as imagens Docker"
        echo "  start         - Iniciar todos os containers"
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
