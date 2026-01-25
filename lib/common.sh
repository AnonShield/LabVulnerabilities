#!/bin/bash
# =============================================================================
# VulnLab - Common Functions Library
#
# This module contains shared utility functions for VulnLab scripts.
# It applies the DRY (Don't Repeat Yourself) principle.
#
# Usage:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
#   or
#   source "/path/to/lib/common.sh"
#
# Author: VulnLab Project
# Version: 1.1.0
# =============================================================================

# Avoid reloading if already loaded
[[ -n "${_VULNLAB_COMMON_LOADED:-}" ]] && return 0
readonly _VULNLAB_COMMON_LOADED=1

# =============================================================================
# ANSI COLORS
# =============================================================================

# Colors for terminal output
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_NC='\033[0m'  # No Color / Reset

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

# Log info message (blue)
log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_NC} $1"
}

# Log success message (green)
log_success() {
    echo -e "${COLOR_GREEN}[OK]${COLOR_NC} $1"
}

# Log warning message (yellow)
log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_NC} $1"
}

# Log error message (red)
log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1" >&2
}

# Log debug message (cyan) - only displays if DEBUG=1
log_debug() {
    [[ "${DEBUG:-0}" == "1" ]] && echo -e "${COLOR_CYAN}[DEBUG]${COLOR_NC} $1"
}

# Log progress message (yellow)
log_progress() {
    echo -e "${COLOR_YELLOW}[INFO]${COLOR_NC} $1"
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

# Validate if a string is a valid IPv4 address
# Usage: is_valid_ipv4 "192.168.1.1" && echo "valid"
is_valid_ipv4() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ ! "$ip" =~ $regex ]]; then
        return 1
    fi

    # Check if each octet is between 0 and 255
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ((octet < 0 || octet > 255)); then
            return 1
        fi
    done

    return 0
}

# Check if a command exists on the system
# Usage: require_command "docker" || exit 1
require_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Command '$cmd' not found. Please install it first."
        return 1
    fi
    return 0
}

# Check if a file exists
# Usage: require_file "/path/to/file" || exit 1
require_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        return 1
    fi
    return 0
}

# Check if a directory exists
# Usage: require_dir "/path/to/dir" || exit 1
require_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        log_error "Directory not found: $dir"
        return 1
    fi
    return 0
}

# =============================================================================
# DOCKER FUNCTIONS
# =============================================================================

# Detect the docker compose command (v1 or v2)
# Usage: COMPOSE_CMD=$(detect_compose_cmd)
detect_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    elif docker-compose --version &> /dev/null; then
        echo "docker-compose"
    else
        log_error "Docker Compose is not installed or not in the PATH!"
        return 1
    fi
}

# Check if a Docker container is running
# Usage: is_container_running "container_name" && echo "running"
is_container_running() {
    local container="$1"
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"
}

# Get the IP address of a Docker container
# Usage: ip=$(get_container_ip "container_name")
get_container_ip() {
    local container="$1"
    docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container" 2>/dev/null
}

# Get the IP addresses of running containers
# Usage: get_container_ips
get_container_ips() {
    local COMPOSE_CMD
    COMPOSE_CMD=$(detect_compose_cmd) || exit 1
    $COMPOSE_CMD ps -q | xargs -I {} docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} | sed 's/^\///' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
}

# =============================================================================
# CLEANUP AND TRAP FUNCTIONS
# =============================================================================

# Array to store cleanup functions
declare -a _CLEANUP_FUNCTIONS=()

# Register a function to be executed on cleanup
# Usage: register_cleanup "my_cleanup_function"
register_cleanup() {
    _CLEANUP_FUNCTIONS+=("$1")
}

# Run all registered cleanup functions
_run_cleanup() {
    local exit_code=$?
    log_debug "Running cleanup (exit code: $exit_code)..."

    for func in "${_CLEANUP_FUNCTIONS[@]}"; do
        if declare -f "$func" > /dev/null; then
            log_debug "Executing: $func"
            "$func" || true
        fi
    done

    exit $exit_code
}

# Setup traps for interrupt signals
# Usage: setup_traps (call at the beginning of the script)
setup_traps() {
    trap '_run_cleanup' EXIT
    trap 'log_warn "Interruption received (SIGINT)"; exit 130' INT
    trap 'log_warn "Termination received (SIGTERM)"; exit 143' TERM
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Display a decorative banner
# Usage: show_banner "Title" "Subtitle"
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

# Wait for a number of seconds with visual feedback
# Usage: wait_with_message 10 "Waiting for service to start"
wait_with_message() {
    local seconds="$1"
    local message="${2:-Waiting}"

    for ((i=seconds; i>0; i--)); do
        printf "\r${COLOR_YELLOW}%s... %ds remaining${COLOR_NC}   " "$message" "$i"
        sleep 1
    done
    printf "\r%-60s\r" " "  # Clear the line
}

# Confirm an action with the user (y/n)
# Usage: confirm "Do you want to continue?" && echo "Yes" || echo "No"
confirm() {
    local prompt="${1:-Continue?}"
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

# Create a directory if it doesn't exist
# Usage: ensure_dir "/path/to/dir"
ensure_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        log_debug "Directory created: $dir"
    fi
}

# Get the root directory of the VulnLab project
# Usage: PROJECT_ROOT=$(get_project_root)
get_project_root() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd)"

    # Go up until docker-compose.yml is found
    local dir="$script_dir"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/docker-compose.yml" ]] && [[ -f "$dir/lab.sh" ]]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done

    # Fallback: return the parent directory of lib/
    dirname "$script_dir"
}

# =============================================================================
# INITIALIZATION
# =============================================================================

# Define PROJECT_ROOT if not set
: "${PROJECT_ROOT:=$(get_project_root)}"
export PROJECT_ROOT