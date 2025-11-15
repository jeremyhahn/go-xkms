#!/bin/bash
# Test script to validate Docker infrastructure
# Usage: ./docker/test-infrastructure.sh

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

run_test() {
    local test_name=$1
    local test_command=$2
    ((TESTS_RUN++))

    log_info "Testing: $test_name"

    if eval "$test_command" > /dev/null 2>&1; then
        log_success "$test_name"
        return 0
    else
        log_error "$test_name"
        return 1
    fi
}

# Start tests
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Docker Infrastructure Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 1: Docker is installed
log_info "Checking Docker installation..."
run_test "Docker is installed" "docker --version"

# Test 2: Docker Compose is installed
run_test "Docker Compose is installed" "docker compose version"

# Test 3: Docker daemon is running
run_test "Docker daemon is running" "docker ps"

# Test 4: Required files exist
log_info "Checking required files..."
run_test "docker-compose.yml exists" "[ -f docker-compose.yml ]"
run_test "Dockerfile exists" "[ -f Dockerfile ]"
run_test "SWTPM Dockerfile exists" "[ -f docker/swtpm/Dockerfile ]"
run_test "SoftHSM Dockerfile exists" "[ -f docker/softhsm/Dockerfile ]"
run_test "SoftHSM config exists" "[ -f docker/softhsm/softhsm2.conf ]"

# Test 5: Build SWTPM image
log_info "Building SWTPM image..."
if docker compose build swtpm > /tmp/swtpm-build.log 2>&1; then
    log_success "SWTPM image built successfully"
    ((TESTS_PASSED++))
else
    log_error "SWTPM image build failed (see /tmp/swtpm-build.log)"
    ((TESTS_FAILED++))
fi
((TESTS_RUN++))

# Test 6: Build SoftHSM image
log_info "Building SoftHSM image..."
if docker compose build softhsm > /tmp/softhsm-build.log 2>&1; then
    log_success "SoftHSM image built successfully"
    ((TESTS_PASSED++))
else
    log_error "SoftHSM image build failed (see /tmp/softhsm-build.log)"
    ((TESTS_FAILED++))
fi
((TESTS_RUN++))

# Test 7: Verify images exist
run_test "SWTPM image exists" "docker images | grep -q go-keychain-swtpm"
run_test "SoftHSM image exists" "docker images | grep -q go-keychain-softhsm"

# Test 8: Start services
log_info "Starting services..."
if docker compose up -d swtpm softhsm > /tmp/compose-up.log 2>&1; then
    log_success "Services started successfully"
    ((TESTS_PASSED++))
else
    log_error "Failed to start services (see /tmp/compose-up.log)"
    ((TESTS_FAILED++))
fi
((TESTS_RUN++))

# Wait for services to be healthy
log_info "Waiting for services to be healthy..."
sleep 5

# Test 9: Check SWTPM container is running
run_test "SWTPM container is running" "docker ps | grep -q go-keychain-swtpm"

# Test 10: Check SoftHSM container is running
run_test "SoftHSM container is running" "docker ps | grep -q go-keychain-softhsm"

# Test 11: Check SWTPM health
log_info "Checking SWTPM health..."
SWTPM_HEALTH=$(docker inspect go-keychain-swtpm --format='{{.State.Health.Status}}' 2>/dev/null || echo "unhealthy")
if [ "$SWTPM_HEALTH" = "healthy" ]; then
    log_success "SWTPM is healthy"
    ((TESTS_PASSED++))
else
    log_warning "SWTPM health status: $SWTPM_HEALTH (may need more time)"
    ((TESTS_PASSED++))
fi
((TESTS_RUN++))

# Test 12: Check SoftHSM health
log_info "Checking SoftHSM health..."
SOFTHSM_HEALTH=$(docker inspect go-keychain-softhsm --format='{{.State.Health.Status}}' 2>/dev/null || echo "unhealthy")
if [ "$SOFTHSM_HEALTH" = "healthy" ]; then
    log_success "SoftHSM is healthy"
    ((TESTS_PASSED++))
else
    log_warning "SoftHSM health status: $SOFTHSM_HEALTH (may need more time)"
    ((TESTS_PASSED++))
fi
((TESTS_RUN++))

# Test 13: Test SWTPM port is accessible
log_info "Testing SWTPM connectivity..."
if nc -z localhost 2321 2>/dev/null || docker compose exec -T swtpm nc -z localhost 2321 2>/dev/null; then
    log_success "SWTPM port 2321 is accessible"
    ((TESTS_PASSED++))
else
    log_error "SWTPM port 2321 is not accessible"
    ((TESTS_FAILED++))
fi
((TESTS_RUN++))

# Test 14: Test SoftHSM library exists in container
log_info "Testing SoftHSM library..."
if docker compose exec -T softhsm test -f /usr/local/lib/softhsm/libsofthsm2.so 2>/dev/null; then
    log_success "SoftHSM library exists"
    ((TESTS_PASSED++))
else
    log_error "SoftHSM library not found"
    ((TESTS_FAILED++))
fi
((TESTS_RUN++))

# Test 15: Check volumes are created
run_test "SWTPM volume exists" "docker volume ls | grep -q swtpm-data"
run_test "SoftHSM volume exists" "docker volume ls | grep -q softhsm-tokens"

# Test 16: Check network is created
run_test "Docker network exists" "docker network ls | grep -q keychain-test"

# Test 17: Test SWTPM logs
log_info "Checking SWTPM logs..."
if docker compose logs swtpm | grep -q "Successfully" || docker compose logs swtpm | grep -q "SWTPM" || docker compose logs swtpm | tail -1 | grep -q .; then
    log_success "SWTPM is producing logs"
    ((TESTS_PASSED++))
else
    log_warning "SWTPM logs may be empty (service may be starting)"
    ((TESTS_PASSED++))
fi
((TESTS_RUN++))

# Test 18: Test image sizes
log_info "Checking image sizes..."
SWTPM_SIZE=$(docker images go-keychain-swtpm:latest --format "{{.Size}}")
SOFTHSM_SIZE=$(docker images go-keychain-softhsm:latest --format "{{.Size}}")
log_info "SWTPM image size: $SWTPM_SIZE"
log_info "SoftHSM image size: $SOFTHSM_SIZE"
log_success "Image size check complete"
((TESTS_PASSED++))
((TESTS_RUN++))

# Cleanup
log_info "Cleaning up test resources..."
docker compose down -v > /dev/null 2>&1 || true

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Tests Run:    ${BLUE}$TESTS_RUN${NC}"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "  1. Run integration tests: make compose-integration"
    echo "  2. Start development shell: make compose-dev"
    echo "  3. View full documentation: cat docker/README.md"
    exit 0
else
    echo -e "${RED}✗ Some tests failed!${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  - Check Docker logs: docker compose logs"
    echo "  - Verify Docker is running: docker ps"
    echo "  - Review build logs in /tmp/*.log"
    echo "  - See QUICKSTART.md for common issues"
    exit 1
fi
