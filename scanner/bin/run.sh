#!/bin/bash
# ============================================================================
# OpenVAS Scanner - Run Script
# Wrapper conveniente para executar o scanner
#
# Autor: VulnLab Project
# Versão: 1.1.0
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Carrega biblioteca comum
source "${SCRIPT_DIR}/../lib/common.sh"

# Ativar ambiente virtual (exceto para setup e help)
if [[ "$1" != "setup" && "$1" != "help" && "$1" != "--help" && "$1" != "-h" ]]; then
    if [ -d "venv" ]; then
        source venv/bin/activate
    else
        echo -e "${COLOR_RED}ERRO: Ambiente virtual não encontrado. Execute primeiro:${COLOR_NC}"
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
        echo -e "${COLOR_RED}ERRO: Container OpenVAS não está rodando!${COLOR_NC}"
        echo "Inicie com: docker start openvas"
        exit 1
    fi
}

case "${1:-help}" in
    all)
        check_openvas
        echo -e "${COLOR_BLUE}Escaneando TODOS os containers do VulnLab...${COLOR_NC}"
        python3 openvas_scanner.py --auto "${@:2}"
        ;;

    webapps)
        check_openvas
        echo -e "${COLOR_BLUE}Escaneando aplicações web...${COLOR_NC}"
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
        echo -e "${COLOR_BLUE}Escaneando bancos de dados...${COLOR_NC}"
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
        echo -e "${COLOR_BLUE}Escaneando containers com CVEs críticas...${COLOR_NC}"
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
            echo -e "${COLOR_YELLOW}Gerando targets.txt...${COLOR_NC}"
            cd .. && ./lab.sh export-targets && cd scanner
        fi
        echo -e "${COLOR_BLUE}Escaneando IPs de targets.txt...${COLOR_NC}"
        python3 openvas_scanner.py -f ../targets.txt "${@:2}"
        ;;

    single)
        check_openvas
        if [ -z "$2" ]; then
            echo -e "${COLOR_RED}ERRO: Especifique o IP${COLOR_NC}"
            echo "Uso: $0 single 172.30.9.1"
            exit 1
        fi
        echo -e "${COLOR_BLUE}Escaneando $2...${COLOR_NC}"
        python3 openvas_scanner.py -i "$2" "${@:3}"
        ;;

    status)
        echo -e "${COLOR_BLUE}Status dos scans:${COLOR_NC}"
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
        echo -e "${COLOR_BLUE}Retomando scans pendentes...${COLOR_NC}"
        python3 openvas_scanner.py --auto
        ;;

    reset)
        echo -e "${COLOR_YELLOW}Limpando estado...${COLOR_NC}"
        rm -f scanner_state.json
        echo -e "${COLOR_GREEN}Estado limpo. Próximo scan começará do zero.${COLOR_NC}"
        ;;

    setup)
        bash setup.sh
        ;;

    help|--help|-h)
        show_help
        ;;

    *)
        echo -e "${COLOR_RED}Comando desconhecido: $1${COLOR_NC}"
        show_help
        exit 1
        ;;
esac
