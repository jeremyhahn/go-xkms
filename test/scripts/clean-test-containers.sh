#!/bin/bash
# Clean up Docker containers left over from integration tests
# This prevents port conflicts when running tests

echo "Cleaning up integration test Docker containers..."

# First, stop any containers using the ports we need
echo "Checking for processes using test ports..."
for port in 8443 9443 8444 9444 9090 2321 2322; do
    container_id=$(docker ps -q --filter "publish=$port" 2>/dev/null)
    if [ -n "$container_id" ]; then
        echo "Stopping container using port $port: $container_id"
        docker stop $container_id 2>/dev/null || true
        docker rm -f $container_id 2>/dev/null || true
    fi
done

# Force kill keychain integration test containers (API tests)
docker kill keychain-integration-server keychain-integration-swtpm keychain-integration-softhsm keychain-integration-tests 2>/dev/null || true
docker rm -f keychain-integration-server keychain-integration-swtpm keychain-integration-softhsm keychain-integration-tests 2>/dev/null || true

# Force kill protocol-specific test containers
docker kill keychain-test-unix keychain-test-rest keychain-test-grpc keychain-test-quic keychain-test-mcp keychain-test-frost keychain-test-parity 2>/dev/null || true
docker rm -f keychain-test-unix keychain-test-rest keychain-test-grpc keychain-test-quic keychain-test-mcp keychain-test-frost keychain-test-parity 2>/dev/null || true

# Stop and remove swtpm containers
docker stop $(docker ps -aq --filter "name=swtpm") 2>/dev/null || true
docker rm -f $(docker ps -aq --filter "name=swtpm") 2>/dev/null || true

# Stop and remove TPM containers
docker stop $(docker ps -aq --filter "name=tpm-simulator") 2>/dev/null || true
docker rm -f $(docker ps -aq --filter "name=tpm-simulator") 2>/dev/null || true

# Stop and remove SoftHSM containers
docker stop $(docker ps -aq --filter "name=softhsm") 2>/dev/null || true
docker rm -f $(docker ps -aq --filter "name=softhsm") 2>/dev/null || true

# Stop and remove Vault containers
docker stop $(docker ps -aq --filter "name=vault") 2>/dev/null || true
docker rm -f $(docker ps -aq --filter "name=vault") 2>/dev/null || true

# Stop and remove emulator containers
docker stop $(docker ps -aq --filter "name=localstack") 2>/dev/null || true
docker rm -f $(docker ps -aq --filter "name=localstack") 2>/dev/null || true

docker stop $(docker ps -aq --filter "name=azure") 2>/dev/null || true
docker rm -f $(docker ps -aq --filter "name=azure") 2>/dev/null || true

docker stop $(docker ps -aq --filter "name=gcp") 2>/dev/null || true
docker rm -f $(docker ps -aq --filter "name=gcp") 2>/dev/null || true

# Remove test networks
docker network prune -f 2>/dev/null || true

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
