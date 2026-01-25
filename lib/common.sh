#!/bin/bash
# =============================================================================
# VulnLab - Biblioteca Comum de Funções
#
# Este módulo contém funções utilitárias compartilhadas entre os scripts
# do VulnLab. Aplica o princípio DRY (Don't Repeat Yourself).
#
# Uso:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
#   ou
#   source "/caminho/para/lib/common.sh"
#
# Autor: VulnLab Project
# Versão: 1.0.0
# =============================================================================

# Evita recarregar se já foi carregado
[[ -n "${_VULNLAB_COMMON_LOADED:-}" ]] && return 0
readonly _VULNLAB_COMMON_LOADED=1

# =============================================================================
# CORES ANSI
# =============================================================================

# Cores para output colorido no terminal
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_NC='\033[0m'  # No Color / Reset

# =============================================================================
# FUNÇÕES DE LOGGING
# =============================================================================

# Log de informação (azul)
log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_NC} $1"
}

# Log de sucesso (verde)
log_success() {
    echo -e "${COLOR_GREEN}[OK]${COLOR_NC} $1"
}

# Log de aviso (amarelo)
log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_NC} $1"
}

# Log de erro (vermelho)
log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1" >&2
}

# Log de debug (ciano) - só exibe se DEBUG=1
log_debug() {
    [[ "${DEBUG:-0}" == "1" ]] && echo -e "${COLOR_CYAN}[DEBUG]${COLOR_NC} $1"
}

# Log de progresso (amarelo, sem quebra de linha para atualizações)
log_progress() {
    echo -e "${COLOR_YELLOW}[INFO]${COLOR_NC} $1"
}

# =============================================================================
# FUNÇÕES DE VALIDAÇÃO
# =============================================================================

# Valida se uma string é um endereço IPv4 válido
# Uso: is_valid_ipv4 "192.168.1.1" && echo "válido"
is_valid_ipv4() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ ! "$ip" =~ $regex ]]; then
        return 1
    fi

    # Verifica se cada octeto está entre 0 e 255
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ((octet < 0 || octet > 255)); then
            return 1
        fi
    done

    return 0
}

# Verifica se um comando existe no sistema
# Uso: require_command "docker" || exit 1
require_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Comando '$cmd' não encontrado. Por favor, instale-o primeiro."
        return 1
    fi
    return 0
}

# Verifica se um arquivo existe
# Uso: require_file "/path/to/file" || exit 1
require_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "Arquivo não encontrado: $file"
        return 1
    fi
    return 0
}

# Verifica se um diretório existe
# Uso: require_dir "/path/to/dir" || exit 1
require_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        log_error "Diretório não encontrado: $dir"
        return 1
    fi
    return 0
}

# =============================================================================
# FUNÇÕES DE DOCKER
# =============================================================================

# Detecta o comando docker compose (v1 ou v2)
# Uso: COMPOSE_CMD=$(detect_compose_cmd)
detect_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    elif docker-compose --version &> /dev/null; then
        echo "docker-compose"
    else
        log_error "Docker Compose não está instalado ou não está no PATH!"
        return 1
    fi
}

# Verifica se um container Docker está rodando
# Uso: is_container_running "container_name" && echo "rodando"
is_container_running() {
    local container="$1"
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"
}

# Obtém o IP de um container Docker
# Uso: ip=$(get_container_ip "container_name")
get_container_ip() {
    local container="$1"
    docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container" 2>/dev/null
}

# =============================================================================
# FUNÇÕES DE LIMPEZA E TRAP
# =============================================================================

# Array para armazenar funções de cleanup
declare -a _CLEANUP_FUNCTIONS=()

# Registra uma função para ser executada no cleanup
# Uso: register_cleanup "minha_funcao_cleanup"
register_cleanup() {
    _CLEANUP_FUNCTIONS+=("$1")
}

# Executa todas as funções de cleanup registradas
_run_cleanup() {
    local exit_code=$?
    log_debug "Executando cleanup (exit code: $exit_code)..."

    for func in "${_CLEANUP_FUNCTIONS[@]}"; do
        if declare -f "$func" > /dev/null; then
            log_debug "Executando: $func"
            "$func" || true
        fi
    done

    exit $exit_code
}

# Configura traps para sinais de interrupção
# Uso: setup_traps (chamar no início do script)
setup_traps() {
    trap '_run_cleanup' EXIT
    trap 'log_warn "Interrupção recebida (SIGINT)"; exit 130' INT
    trap 'log_warn "Terminação recebida (SIGTERM)"; exit 143' TERM
}

# =============================================================================
# FUNÇÕES UTILITÁRIAS
# =============================================================================

# Exibe um banner decorativo
# Uso: show_banner "Título" "Subtítulo"
show_banner() {
    local title="${1:-VulnLab}"
    local subtitle="${2:-}"

    echo -e "${COLOR_BLUE}"
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    printf "║ %-74s ║\n" "$title"
    [[ -n "$subtitle" ]] && printf "║ %-74s ║\n" "$subtitle"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_NC}"
}

# Aguarda um número de segundos com feedback visual
# Uso: wait_with_message 10 "Aguardando serviço inicializar"
wait_with_message() {
    local seconds="$1"
    local message="${2:-Aguardando}"

    for ((i=seconds; i>0; i--)); do
        printf "\r${COLOR_YELLOW}%s... %ds restantes${COLOR_NC}   " "$message" "$i"
        sleep 1
    done
    printf "\r%-60s\r" " "  # Limpa a linha
}

# Confirma uma ação com o usuário (y/n)
# Uso: confirm "Deseja continuar?" && echo "Sim" || echo "Não"
confirm() {
    local prompt="${1:-Continuar?}"
    local response

    echo -en "${COLOR_YELLOW}${prompt} [y/N]: ${COLOR_NC}"
    read -r response

    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Cria diretório se não existir
# Uso: ensure_dir "/path/to/dir"
ensure_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        log_debug "Diretório criado: $dir"
    fi
}

# Obtém o diretório raiz do projeto VulnLab
# Uso: PROJECT_ROOT=$(get_project_root)
get_project_root() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd)"

    # Sobe até encontrar o docker-compose.yml
    local dir="$script_dir"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/docker-compose.yml" ]] && [[ -f "$dir/lab.sh" ]]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done

    # Fallback: retorna o diretório pai do lib/
    dirname "$script_dir"
}

# =============================================================================
# INICIALIZAÇÃO
# =============================================================================

# Define PROJECT_ROOT se não estiver definido
: "${PROJECT_ROOT:=$(get_project_root)}"
export PROJECT_ROOT
