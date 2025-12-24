#!/bin/bash
# Clean up Docker containers left over from integration tests
# This prevents port conflicts when running tests

echo "Cleaning up integration test Docker containers..."

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

# Clean up any orphaned containers from compose
docker compose -f test/integration/api/docker-compose.yml down -v --remove-orphans 2>/dev/null || true

echo "Cleanup complete!"
