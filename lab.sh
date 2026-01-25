#!/bin/bash
# =============================================================================
# VULNLAB - Vulnerable Applications Laboratory
# Environment for pentesting, security training, and scanner testing
#
# Author: VulnLab Project
# Version: 2.1.0
# =============================================================================

set -e

# Load common library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# Compatibility with old functions (alias)
show_progress() { log_progress "$1"; }
show_success() { log_success "$1"; }

# Banner
show_banner "VULNLAB - Vulnerability Lab" "Vulnerable Applications Laboratory for Pentesting"

# Detect docker compose command
COMPOSE_CMD=$(detect_compose_cmd) || exit 1

# Note: setup_traps removed as it interferes with exit codes in simple scripts
# For more complex scripts with cleanup, enable: setup_traps

# Validate if docker-compose.yml exists
require_file "${SCRIPT_DIR}/docker-compose.yml" || exit 1

# Function to validate if a service exists in compose
validate_service() {
    local service="$1"
    local all_services
    all_services=$($COMPOSE_CMD config --services 2>/dev/null)
    if ! echo "$all_services" | grep -qx "$service"; then
        log_warn "Service '$service' not found in docker-compose.yml"
        return 1
    fi
    return 0
}

# Main menu
case "${1:-}" in
    pull)
        show_progress "Pulling all Docker images..."
        $COMPOSE_CMD pull --ignore-pull-failures
        show_success "Download complete!"
        ;;
    
    start)
        # Shift past the 'start' command
        shift

        if [ "$#" -gt 0 ]; then
            show_progress "Starting a subset of containers (Smoke Test)..."
            SERVICES=""
            # Validate each service before adding to the list
            for svc in "$@"; do
                if validate_service "$svc"; then
                    SERVICES="$SERVICES $svc"
                fi
            done
            SERVICES=$(echo "$SERVICES" | xargs)  # Trim whitespace
            if [ -z "$SERVICES" ]; then
                log_error "No valid services specified."
                exit 1
            fi
        else
            show_progress "Starting all containers resiliently..."
            SERVICES=$($COMPOSE_CMD config --services)
        fi

        # Ensure the logs directory exists
        ensure_dir logs

        # Success/failure counter
        SUCCESS_COUNT=0
        FAIL_COUNT=0

        for SERVICE in $SERVICES; do
            echo -e "${COLOR_YELLOW}--> Starting service: $SERVICE...${COLOR_NC}"
            # Try to start the service, capturing output
            if output=$($COMPOSE_CMD up -d --no-deps "$SERVICE" 2>&1); then
                echo -e "${COLOR_GREEN}    Service $SERVICE started successfully.${COLOR_NC}"
                ((SUCCESS_COUNT++)) || true
            else
                echo -e "${COLOR_RED}    ERROR starting service $SERVICE. Saving log to logs/$SERVICE.log${COLOR_NC}"
                echo "$output" > "logs/$SERVICE.log"
                ((FAIL_COUNT++)) || true
            fi
        done

        show_success "Startup process complete!"
        echo ""
        echo -e "Summary: ${COLOR_GREEN}$SUCCESS_COUNT successful${COLOR_NC} | ${COLOR_RED}$FAIL_COUNT failed${COLOR_NC}"
        echo -e "${COLOR_BLUE}Wait for services to initialize completely.${COLOR_NC}"
        true  # Ensure exit code 0
        ;;
    
    stop)
        show_progress "Stopping all containers..."
        $COMPOSE_CMD down
        show_success "Containers stopped!"
        ;;
    
    status)
        echo -e "${COLOR_BLUE}=== STATUS OF ALL CONTAINERS ===${COLOR_NC}"
        $COMPOSE_CMD ps -a
        echo ""
        echo -e "${COLOR_BLUE}=== SUMMARY ===${COLOR_NC}"
        # Use docker directly for more reliable counting
        RUNNING=$(docker ps -q 2>/dev/null | wc -l)
        TOTAL=$(docker ps -a -q 2>/dev/null | wc -l)
        EXITED=$((TOTAL - RUNNING))
        echo -e "Running: ${COLOR_GREEN}$RUNNING${COLOR_NC}"
        echo -e "Stopped/Errored: ${COLOR_RED}$EXITED${COLOR_NC}"
        echo -e "Total: $TOTAL"
        ;;
    
    logs)
        if [ -z "${2:-}" ]; then
            echo "Usage: $0 logs <container-name>"
            exit 1
        fi
        $COMPOSE_CMD logs -f "$2"
        ;;
    
    ips)
        echo -e "${COLOR_BLUE}=== CONTAINER IPs ===${COLOR_NC}"
        get_container_ips
        ;;
    
    scan-targets)
        echo -e "${COLOR_BLUE}=== TARGET LIST FOR OPENVAS ===${COLOR_NC}"
        echo "Networks: 172.30.0.0/15"
        echo ""
        echo "Or use specific IPs:"
        get_container_ips | awk '{print $3}'
        ;;
    
    export-targets)
        echo -e "${COLOR_BLUE}Exporting IP list to targets.txt...${COLOR_NC}"
        get_container_ips | awk '{print $3}' > targets.txt
        show_success "File targets.txt created with $(wc -l < targets.txt) targets!"
        ;;
    
    restart)
        show_progress "Restarting all containers..."
        $COMPOSE_CMD restart
        show_success "Containers restarted!"
        ;;
    
    clean)
        show_progress "Stopping and removing compose containers..."
        $COMPOSE_CMD down -v
        show_progress "Removing any remaining stopped containers..."
        docker container prune -f
        show_success "Cleanup complete!"
        ;;
    
    stats)
        echo -e "${COLOR_BLUE}=== RESOURCE STATISTICS ===${COLOR_NC}"
        docker stats --no-stream
        ;;
        
    *)
        echo "Usage: $0 {pull|start|stop|status|logs|ips|scan-targets|export-targets|restart|clean|stats}"
        echo "For smoke test: $0 start <service1> <service2> ..."
        echo ""
        echo "Commands:"
        echo "  pull          - Download all Docker images"
        echo "  start         - Start all containers (or a subset)"
        echo "  stop          - Stop all containers"
        echo "  status        - View status of containers"
        echo "  logs <name>   - View logs of a specific container"
        echo "  ips           - List IPs of all containers"
        echo "  scan-targets  - Show list of targets for scanning"
        echo "  export-targets- Export IPs to targets.txt file"
        echo "  restart       - Restart all containers"
        echo "  clean         - Remove containers and volumes"
        echo "  stats         - View resource usage"
        exit 1
        ;;
esac
