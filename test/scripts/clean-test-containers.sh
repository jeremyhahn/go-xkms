#!/bin/bash
# Clean up Docker containers left over from integration tests
# This prevents port conflicts when running tests
#
# IMPORTANT: This script preserves devcontainer infrastructure (xkms-dev-* containers
# and the devcontainer_xkms-dev network). Only test-specific containers are cleaned.

echo "Cleaning up integration test Docker containers..."

# Helper: stop and remove containers matching a name filter,
# but exclude devcontainer-owned containers (xkms-dev-* and devcontainer-*)
clean_containers() {
    local filter="$1"
    local ids
    ids=$(docker ps -aq --filter "name=$filter" 2>/dev/null | while read -r id; do
        name=$(docker inspect --format '{{.Name}}' "$id" 2>/dev/null | sed 's|^/||')
        case "$name" in
            xkms-dev-*|devcontainer-*) ;;  # skip devcontainer containers
            *) echo "$id" ;;
        esac
    done)
    if [ -n "$ids" ]; then
        docker stop $ids 2>/dev/null || true
        docker rm -f $ids 2>/dev/null || true
    fi
}

# First, stop any containers using the ports we need
# Skip ports that belong to the devcontainer xkms-server (started separately)
echo "Checking for processes using test ports..."
for port in 8443 9443 8444 9444 9090 2321 2322; do
    container_id=$(docker ps -q --filter "publish=$port" 2>/dev/null)
    if [ -n "$container_id" ]; then
        # Check if this container belongs to the devcontainer
        name=$(docker inspect --format '{{.Name}}' "$container_id" 2>/dev/null | sed 's|^/||')
        case "$name" in
            xkms-dev-*|devcontainer-*)
                echo "Skipping devcontainer container on port $port: $name"
                ;;
            *)
                echo "Stopping container using port $port: $container_id ($name)"
                docker stop "$container_id" 2>/dev/null || true
                docker rm -f "$container_id" 2>/dev/null || true
                ;;
        esac
    fi
done

# Force kill xkms integration test containers (API tests)
docker kill xkms-integration-server xkms-integration-swtpm xkms-integration-softhsm xkms-integration-tests 2>/dev/null || true
docker rm -f xkms-integration-server xkms-integration-swtpm xkms-integration-softhsm xkms-integration-tests 2>/dev/null || true

# Force kill protocol-specific test containers
docker kill xkms-test-unix xkms-test-rest xkms-test-grpc xkms-test-quic xkms-test-mcp xkms-test-frost xkms-test-parity 2>/dev/null || true
docker rm -f xkms-test-unix xkms-test-rest xkms-test-grpc xkms-test-quic xkms-test-mcp xkms-test-frost xkms-test-parity 2>/dev/null || true

# Stop and remove test swtpm containers (but not xkms-dev-swtpm)
clean_containers "swtpm"

# Stop and remove TPM simulator containers
clean_containers "tpm-simulator"

# Stop and remove test SoftHSM containers (but not xkms-dev-softhsm)
clean_containers "softhsm"

# Stop and remove Vault containers
clean_containers "vault"

# Stop and remove emulator containers
clean_containers "localstack"
clean_containers "azure"
clean_containers "gcp"

# Remove only test-specific networks (NOT the devcontainer network)
echo "Cleaning test-specific networks..."
docker network ls --format '{{.Name}}' 2>/dev/null | while read -r net; do
    case "$net" in
        devcontainer_*|xkms-dev|bridge|host|none) ;;  # preserve these
        *test*|*integration*)
            echo "Removing test network: $net"
            docker network rm "$net" 2>/dev/null || true
            ;;
    esac
done

# Clean up any orphaned containers from all integration test compose files
for compose_file in test/integration/*/docker-compose.yml; do
    if [ -f "$compose_file" ]; then
        echo "Cleaning up $compose_file..."
        docker compose -f "$compose_file" down -v --remove-orphans 2>/dev/null || true
    fi
done

# Also handle nested compose files (e.g., tpm2/idevid, tpm2/tpm_operations)
for compose_file in test/integration/*/*/docker-compose.yml; do
    if [ -f "$compose_file" ]; then
        echo "Cleaning up $compose_file..."
        docker compose -f "$compose_file" down -v --remove-orphans 2>/dev/null || true
    fi
done

# Clean up dangling images and build cache to free disk space (CI)
if [ "${CI:-}" = "true" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "CI environment detected - performing aggressive cleanup..."
    docker image prune -f 2>/dev/null || true
    docker builder prune -f 2>/dev/null || true
fi

echo "Cleanup complete!"
