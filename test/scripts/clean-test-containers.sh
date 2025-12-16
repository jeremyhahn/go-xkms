#!/bin/bash
# Clean up Docker containers left over from integration tests
# This prevents port conflicts when running tests

echo "Cleaning up integration test Docker containers..."

# Stop and remove TPM containers
docker stop $(docker ps -aq --filter "name=tpm-simulator") 2>/dev/null
docker rm $(docker ps -aq --filter "name=tpm-simulator") 2>/dev/null

# Stop and remove SoftHSM containers
docker stop $(docker ps -aq --filter "name=softhsm") 2>/dev/null
docker rm $(docker ps -aq --filter "name=softhsm") 2>/dev/null

# Stop and remove Vault containers
docker stop $(docker ps -aq --filter "name=vault") 2>/dev/null
docker rm $(docker ps -aq --filter "name=vault") 2>/dev/null

# Stop and remove emulator containers
docker stop $(docker ps -aq --filter "name=localstack") 2>/dev/null
docker rm $(docker ps -aq --filter "name=localstack") 2>/dev/null

docker stop $(docker ps -aq --filter "name=azure") 2>/dev/null
docker rm $(docker ps -aq --filter "name=azure") 2>/dev/null

docker stop $(docker ps -aq --filter "name=gcp") 2>/dev/null
docker rm $(docker ps -aq --filter "name=gcp") 2>/dev/null

# Remove test networks
docker network prune -f 2>/dev/null

echo "Cleanup complete!"
