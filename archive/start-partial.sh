#!/bin/bash
# =============================================================================
# PARTIAL START SCRIPT
# Inicia containers em grupos para sistemas com recursos limitados
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║           VULNERABILITY LAB - PARTIAL START                            ║"
echo "║           Use quando tiver recursos limitados                          ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

case "${1:-}" in
    infra)
        echo -e "${YELLOW}[INFO] Iniciando INFRAESTRUTURA (FTP, SSH, SMB, DNS)...${NC}"
        docker compose up -d \
            metasploitable2 \
            vsftpd-backdoor \
            proftpd-vuln \
            ssh-cve-2016-6515 \
            ubuntu-sshd-old \
            sambacry \
            dns-vuln
        ;;
    
    cves)
        echo -e "${YELLOW}[INFO] Iniciando CVEs FAMOSAS (Shellshock, Heartbleed, Log4Shell)...${NC}"
        docker compose up -d \
            shellshock \
            heartbleed \
            apache-cve-2021-41773 \
            log4shell \
            struts2-cve-2017-5638 \
            tomcat-cgi \
            haraka-rce \
            spring-oauth-rce \
            phpmailer-rce
        ;;
    
    webapps)
        echo -e "${YELLOW}[INFO] Iniciando WEB APPS VULNERÁVEIS...${NC}"
        docker compose up -d \
            juice-shop \
            hackazon \
            altoromutual \
            dvwa \
            bwapp \
            mutillidae \
            xvwa
        ;;
    
    owasp)
        echo -e "${YELLOW}[INFO] Iniciando OWASP GOAT SERIES...${NC}"
        docker compose up -d \
            webgoat \
            nodegoat \
            railsgoat \
            security-shepherd
        ;;
    
    apis)
        echo -e "${YELLOW}[INFO] Iniciando APIs VULNERÁVEIS...${NC}"
        docker compose up -d \
            crapi \
            vampi \
            tiredful-api \
            damn-vulnerable-graphql
        ;;
    
    databases)
        echo -e "${YELLOW}[INFO] Iniciando BANCOS DE DADOS...${NC}"
        docker compose up -d \
            mysql-old \
            postgres-old \
            mongodb-noauth \
            redis-noauth \
            elasticsearch-old \
            couchdb-old
        ;;
    
    enterprise)
        echo -e "${YELLOW}[INFO] Iniciando ENTERPRISE (Jenkins, GitLab, WebLogic)...${NC}"
        docker compose up -d \
            jenkins-vuln \
            gitlab-vuln \
            weblogic-vuln \
            jboss-vuln
        ;;
    
    monitoring)
        echo -e "${YELLOW}[INFO] Iniciando MONITORAMENTO E MESSAGING...${NC}"
        docker compose up -d \
            kibana-old \
            grafana-old \
            rabbitmq-old \
            activemq-old
        ;;
    
    minimal)
        echo -e "${YELLOW}[INFO] Iniciando CONFIGURAÇÃO MÍNIMA (20 containers mais importantes)...${NC}"
        docker compose up -d \
            metasploitable2 \
            dvwa \
            juice-shop \
            webgoat \
            shellshock \
            heartbleed \
            log4shell \
            struts2-cve-2017-5638 \
            sambacry \
            mysql-old \
            redis-noauth \
            mongodb-noauth \
            jenkins-vuln \
            vsftpd-backdoor \
            ssh-cve-2016-6515 \
            crapi \
            vampi \
            wordpress-vuln \
            grafana-old \
            apache-cve-2021-41773
        ;;
    
    all)
        echo -e "${YELLOW}[INFO] Iniciando TODOS os containers...${NC}"
        docker compose up -d
        ;;
    
    *)
        echo "Uso: $0 {infra|cves|webapps|owasp|apis|databases|enterprise|monitoring|minimal|all}"
        echo ""
        echo "Grupos disponíveis:"
        echo ""
        echo "  infra       - Infraestrutura (FTP, SSH, SMB, DNS) - ~7 containers"
        echo "  cves        - CVEs Famosas (Shellshock, Heartbleed, Log4Shell) - ~9 containers"
        echo "  webapps     - Aplicações Web Vulneráveis - ~7 containers"
        echo "  owasp       - OWASP Goat Series - ~4 containers"
        echo "  apis        - APIs Vulneráveis - ~4 containers"
        echo "  databases   - Bancos de Dados - ~6 containers"
        echo "  enterprise  - Soluções Enterprise - ~4 containers"
        echo "  monitoring  - Monitoramento e Messaging - ~4 containers"
        echo ""
        echo "  minimal     - Configuração mínima recomendada - ~20 containers"
        echo "  all         - Todos os containers - ~100 containers"
        echo ""
        echo "Exemplos:"
        echo "  $0 minimal                    # Começa com o mínimo"
        echo "  $0 infra && $0 cves           # Adiciona grupos incrementalmente"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}[OK] Containers iniciados!${NC}"
echo ""
echo -e "${BLUE}Verificar status: ./lab.sh status${NC}"
echo -e "${BLUE}Ver IPs: ./lab.sh ips${NC}"
