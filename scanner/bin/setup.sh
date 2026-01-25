#!/bin/bash
# ============================================================================
# OpenVAS Scanner - Setup Script
#
# Autor: VulnLab Project
# Versão: 1.1.0
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Carrega biblioteca comum
source "${SCRIPT_DIR}/../lib/common.sh"

show_banner "OpenVAS Automated Scanner - Setup"

# Verificar Python
echo "[1/5] Verificando Python..."
if ! command -v python3 &> /dev/null; then
    echo "ERRO: Python 3 não encontrado. Instale com:"
    echo "  sudo apt install python3 python3-pip python3-venv"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo "  ✓ $PYTHON_VERSION"

# Criar ambiente virtual
echo ""
echo "[2/5] Criando ambiente virtual..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "  ✓ Ambiente virtual criado"
else
    echo "  ✓ Ambiente virtual já existe"
fi

# Ativar venv e instalar dependências
echo ""
echo "[3/5] Instalando dependências Python..."
source venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "  ✓ gvm-tools instalado"
echo "  ✓ PyYAML instalado"

# Verificar conexão com OpenVAS
echo ""
echo "[4/5] Verificando OpenVAS..."
if docker ps --format '{{.Names}}' | grep -q "^openvas$"; then
    echo "  ✓ Container 'openvas' está rodando"

    # Verificar se porta 9390 está exposta
    if docker port openvas 9390 &> /dev/null; then
        echo "  ✓ Porta 9390 (GMP) exposta"
    else
        echo "  ⚠ Porta 9390 não está exposta. O scanner pode não funcionar."
        echo "    Recrie o container com: -p 9390:9390"
    fi

    # Verificar rede
    if docker network inspect trabalho_vulnnet --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | grep -q openvas; then
        echo "  ✓ OpenVAS conectado à rede vulnnet"
    else
        echo "  ⚠ OpenVAS não está na rede vulnnet. Conectando..."
        docker network connect trabalho_vulnnet openvas 2>/dev/null || true
        echo "  ✓ Conectado"
    fi
else
    echo "  ⚠ Container 'openvas' não encontrado ou não está rodando"
    echo "    Inicie com:"
    echo "    docker run -d --name openvas -p 9392:9392 -p 9390:9390 \\"
    echo "      -e PASSWORD=\"admin\" --network trabalho_vulnnet immauss/openvas"
fi

# Criar diretórios
echo ""
echo "[5/5] Criando diretórios..."
mkdir -p reports logs
echo "  ✓ reports/"
echo "  ✓ logs/"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Setup concluído!"
echo ""
echo "Para usar o scanner:"
echo ""
echo "  # Escanear IPs específicos"
echo "  python3 openvas_scanner.py -i 172.30.9.1 172.30.7.1"
echo ""
echo "  # Escanear de um arquivo"
echo "  python3 openvas_scanner.py -f ../targets.txt"
echo ""
echo "  # Escanear todos os containers do VulnLab"
echo "  python3 openvas_scanner.py --auto"
echo ""
echo "  # Ver todas as opções"
echo "  python3 openvas_scanner.py --help"
echo ""
echo "════════════════════════════════════════════════════════════════"
