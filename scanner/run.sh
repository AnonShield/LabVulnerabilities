#!/bin/bash
# ============================================================================
# OpenVAS Scanner - Run Script
# Wrapper conveniente para executar o scanner
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Ativar ambiente virtual (exceto para setup e help)
if [[ "$1" != "setup" && "$1" != "help" && "$1" != "--help" && "$1" != "-h" ]]; then
    if [ -d "venv" ]; then
        source venv/bin/activate
    else
        echo -e "${RED}ERRO: Ambiente virtual não encontrado. Execute primeiro:${NC}"
        echo "  ./setup.sh"
        exit 1
    fi
fi

show_help() {
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║           OpenVAS Automated Scanner                            ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Uso: $0 <comando> [opções]"
    echo ""
    echo "Comandos:"
    echo "  all         Escanear todos os containers do VulnLab"
    echo "  webapps     Escanear apenas aplicações web vulneráveis"
    echo "  databases   Escanear apenas bancos de dados"
    echo "  cves        Escanear containers com CVEs específicas"
    echo "  custom      Escanear IPs de targets.txt"
    echo "  single IP   Escanear um único IP"
    echo "  status      Mostrar status dos scans"
    echo "  resume      Retomar scans pendentes"
    echo "  reset       Limpar estado e começar do zero"
    echo "  setup       Instalar dependências"
    echo ""
    echo "Exemplos:"
    echo "  $0 all              # Todos os containers"
    echo "  $0 webapps          # DVWA, Juice Shop, WebGoat..."
    echo "  $0 single 172.30.9.1"
    echo "  $0 status"
    echo ""
}

check_openvas() {
    if ! docker ps --format '{{.Names}}' | grep -q "^openvas$"; then
        echo -e "${RED}ERRO: Container OpenVAS não está rodando!${NC}"
        echo "Inicie com: docker start openvas"
        exit 1
    fi
}

case "${1:-help}" in
    all)
        check_openvas
        echo -e "${BLUE}Escaneando TODOS os containers do VulnLab...${NC}"
        python3 openvas_scanner.py --auto "${@:2}"
        ;;

    webapps)
        check_openvas
        echo -e "${BLUE}Escaneando aplicações web...${NC}"
        python3 openvas_scanner.py -i \
            172.30.7.1 \
            172.30.7.2 \
            172.30.8.1 \
            172.30.9.1 \
            172.30.9.2 \
            172.30.9.3 \
            172.30.10.2 \
            172.30.10.4 \
            "${@:2}"
        ;;

    databases)
        check_openvas
        echo -e "${BLUE}Escaneando bancos de dados...${NC}"
        python3 openvas_scanner.py -i \
            172.30.14.1 \
            172.30.14.2 \
            172.30.14.3 \
            172.30.14.4 \
            172.30.14.5 \
            172.30.14.6 \
            "${@:2}"
        ;;

    cves)
        check_openvas
        echo -e "${BLUE}Escaneando containers com CVEs críticas...${NC}"
        python3 openvas_scanner.py -i \
            172.30.3.1 \
            172.30.4.1 \
            172.30.6.3 \
            172.30.6.4 \
            172.30.44.2 \
            "${@:2}"
        ;;

    custom)
        check_openvas
        if [ ! -f "../targets.txt" ]; then
            echo -e "${YELLOW}Gerando targets.txt...${NC}"
            cd .. && ./lab.sh export-targets && cd scanner
        fi
        echo -e "${BLUE}Escaneando IPs de targets.txt...${NC}"
        python3 openvas_scanner.py -f ../targets.txt "${@:2}"
        ;;

    single)
        check_openvas
        if [ -z "$2" ]; then
            echo -e "${RED}ERRO: Especifique o IP${NC}"
            echo "Uso: $0 single 172.30.9.1"
            exit 1
        fi
        echo -e "${BLUE}Escaneando $2...${NC}"
        python3 openvas_scanner.py -i "$2" "${@:3}"
        ;;

    status)
        echo -e "${BLUE}Status dos scans:${NC}"
        if [ -f "scanner_state.json" ]; then
            python3 -c "
import json
with open('scanner_state.json') as f:
    state = json.load(f)
scans = state.get('scans', {})
done = sum(1 for s in scans.values() if s.get('status') == 'done')
failed = sum(1 for s in scans.values() if s.get('status') == 'failed')
pending = sum(1 for s in scans.values() if s.get('status') in ['pending', 'running'])
print(f'  Total:     {len(scans)}')
print(f'  Concluído: {done}')
print(f'  Falhou:    {failed}')
print(f'  Pendente:  {pending}')
print()
print('Últimos 5 scans:')
for ip, scan in list(scans.items())[-5:]:
    status = scan.get('status', '?')
    vulns = scan.get('vulnerabilities', {})
    high = vulns.get('high', 0)
    print(f'  {ip}: {status} (High: {high})')
"
        else
            echo "  Nenhum scan realizado ainda."
        fi
        ;;

    resume)
        check_openvas
        echo -e "${BLUE}Retomando scans pendentes...${NC}"
        python3 openvas_scanner.py --auto
        ;;

    reset)
        echo -e "${YELLOW}Limpando estado...${NC}"
        rm -f scanner_state.json
        echo -e "${GREEN}Estado limpo. Próximo scan começará do zero.${NC}"
        ;;

    setup)
        bash setup.sh
        ;;

    help|--help|-h)
        show_help
        ;;

    *)
        echo -e "${RED}Comando desconhecido: $1${NC}"
        show_help
        exit 1
        ;;
esac
