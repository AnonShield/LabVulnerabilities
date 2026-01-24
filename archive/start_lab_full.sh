#!/bin/bash
set -e

# Script para iniciar o laboratório de vulnerabilidades de forma consolidada e resiliente.

# 1. Garante que o contêiner do OpenVAS esteja conectado à rede.
echo "--> Conectando o contêiner 'openvas' à rede 'trabalho_vulnnet' (se necessário)..."
docker network inspect trabalho_vulnnet >/dev/null 2>&1 || docker network create --subnet=172.30.0.0/16 trabalho_vulnnet
docker network connect trabalho_vulnnet openvas || true
echo ""

# 2. Gera o script de inicialização que é resiliente a falhas.
# Este script Python primeiro executa 'docker-compose pull' para obter uma lista atualizada
# de imagens que não podem ser baixadas e, em seguida, gera o 'run_containers.sh'
# que ignora essas imagens e continua mesmo que um contêiner não consiga iniciar.
echo "--> Gerando script de inicialização resiliente 'run_containers.sh'..."
python3 build_and_run_lab.py run_containers.sh
echo ""

# 3. Executa o script para iniciar todos os contêineres vulneráveis.
echo "--> Executando o script para iniciar os contêineres do laboratório..."
./run_containers.sh

echo ""
echo "✅ Processo de inicialização do laboratório concluído!"
echo "Verifique o output acima para ver se algum contêiner individual falhou ao iniciar."
echo "O scan do OpenVAS continua rodando em segundo plano."