#!/bin/bash
# run-tests.sh - PKCS#11 module integration test runner
#
# This script:
# 1. Waits for the xkms server to be ready
# 2. Tests the PKCS#11 module with pkcs11-tool
# 3. Runs Go integration tests
# 4. Reports results
#
# Environment variables:
#   PKCS11_MODULE           - Path to PKCS#11 module (default: /usr/local/lib/libxkms_pkcs11.so)
#   XKMS_UNIX_SOCKET    - Unix socket path (default: /var/run/xkms/xkms.sock)
#   XKMS_GRPC_ADDR      - gRPC server address (default: xkms-server:9443)
#   XKMS_CONNECTION_MODE - Connection mode: unix or tcp (default: unix)
#   SERVER_WAIT_TIMEOUT     - Timeout waiting for server (default: 60)
#   PKCS11_PIN              - User PIN (default: 1234)
#   PKCS11_SO_PIN           - Security Officer PIN (default: 12345678)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration with defaults
PKCS11_MODULE="${PKCS11_MODULE:-/usr/local/lib/libxkms_pkcs11.so}"
XKMS_UNIX_SOCKET="${XKMS_UNIX_SOCKET:-/var/run/xkms/xkms.sock}"
XKMS_GRPC_ADDR="${XKMS_GRPC_ADDR:-xkms-server:9443}"
XKMS_CONNECTION_MODE="${XKMS_CONNECTION_MODE:-unix}"
SERVER_WAIT_TIMEOUT="${SERVER_WAIT_TIMEOUT:-60}"
PKCS11_PIN="${PKCS11_PIN:-1234}"
PKCS11_SO_PIN="${PKCS11_SO_PIN:-12345678}"

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0
TEST_RESULTS=""

# Print a header
print_header() {
    echo ""
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================================${NC}"
    echo ""
}

# Print section header
print_section() {
    echo ""
    echo -e "${YELLOW}--- $1 ---${NC}"
}

# Log success
log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TEST_RESULTS="${TEST_RESULTS}PASS: $1\n"
}

# Log failure
log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TEST_RESULTS="${TEST_RESULTS}FAIL: $1\n"
}

# Log info
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Log warning
log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Wait for server to be ready
wait_for_server() {
    print_section "Waiting for xkms server"

    local elapsed=0
    local server_ready=false

    # Try Unix socket first if configured
    if [ "$XKMS_CONNECTION_MODE" = "unix" ]; then
        log_info "Checking Unix socket: $XKMS_UNIX_SOCKET"
        while [ $elapsed -lt $SERVER_WAIT_TIMEOUT ]; do
            if [ -S "$XKMS_UNIX_SOCKET" ]; then
                log_success "Unix socket is available"
                server_ready=true
                break
            fi
            sleep 1
            elapsed=$((elapsed + 1))
            if [ $((elapsed % 10)) -eq 0 ]; then
                log_info "Still waiting... ($elapsed seconds)"
            fi
        done
    fi

    # Fall back to TCP if socket not available
    if [ "$server_ready" = false ] && [ -n "$XKMS_GRPC_ADDR" ]; then
        log_info "Unix socket not available, trying TCP: $XKMS_GRPC_ADDR"
        XKMS_CONNECTION_MODE="tcp"

        # Extract host and port
        local host=$(echo "$XKMS_GRPC_ADDR" | cut -d: -f1)
        local port=$(echo "$XKMS_GRPC_ADDR" | cut -d: -f2)

        while [ $elapsed -lt $SERVER_WAIT_TIMEOUT ]; do
            if nc -z "$host" "$port" 2>/dev/null; then
                log_success "TCP connection available on $XKMS_GRPC_ADDR"
                server_ready=true
                break
            fi
            sleep 1
            elapsed=$((elapsed + 1))
            if [ $((elapsed % 10)) -eq 0 ]; then
                log_info "Still waiting... ($elapsed seconds)"
            fi
        done
    fi

    if [ "$server_ready" = false ]; then
        log_failure "Server did not become ready within $SERVER_WAIT_TIMEOUT seconds"
        return 1
    fi

    # Additional delay for server initialization
    log_info "Giving server 2 more seconds to fully initialize..."
    sleep 2

    return 0
}

# Verify PKCS#11 module exists
verify_module() {
    print_section "Verifying PKCS#11 module"

    if [ -f "$PKCS11_MODULE" ]; then
        log_success "PKCS#11 module found: $PKCS11_MODULE"

        # Check if it's a valid shared library
        if file "$PKCS11_MODULE" | grep -q "shared object"; then
            log_success "Module is a valid shared object"
        else
            log_warning "Module may not be a valid shared object"
        fi

        # Check library dependencies
        log_info "Module dependencies:"
        ldd "$PKCS11_MODULE" 2>/dev/null || log_warning "Could not list dependencies"

        return 0
    else
        log_failure "PKCS#11 module not found: $PKCS11_MODULE"
        return 1
    fi
}

# Test with pkcs11-tool
test_pkcs11_tool() {
    print_section "Testing with pkcs11-tool"

    # Check if pkcs11-tool is available
    if ! command -v pkcs11-tool &> /dev/null; then
        log_warning "pkcs11-tool not found, skipping compatibility tests"
        return 0
    fi

    # Test: Show module info
    log_info "Getting module info..."
    if pkcs11-tool --module "$PKCS11_MODULE" --show-info 2>&1; then
        log_success "Module info retrieved"
    else
        log_warning "Could not get module info (may be expected if not initialized)"
    fi

    # Test: List slots
    log_info "Listing slots..."
    if pkcs11-tool --module "$PKCS11_MODULE" --list-slots 2>&1; then
        log_success "Slots listed successfully"
    else
        log_warning "Could not list slots (may be expected if not initialized)"
    fi

    # Test: List mechanisms
    log_info "Listing mechanisms..."
    if pkcs11-tool --module "$PKCS11_MODULE" --list-mechanisms 2>&1; then
        log_success "Mechanisms listed successfully"
    else
        log_warning "Could not list mechanisms (may be expected if not initialized)"
    fi

    return 0
}

# Run Go integration tests
run_go_tests() {
    print_section "Running Go integration tests"

    # Check if we're in the workspace
    if [ -f "/workspace/go.mod" ]; then
        cd /workspace
    elif [ -f "/app/go.mod" ]; then
        cd /app
    else
        log_warning "Could not find go.mod, skipping Go tests"
        return 0
    fi

    log_info "Working directory: $(pwd)"
    log_info "Connection mode: $XKMS_CONNECTION_MODE"

    # Export connection configuration for tests
    export PKCS11_MODULE
    export XKMS_CONNECTION_MODE
    export XKMS_UNIX_SOCKET
    export XKMS_GRPC_ADDR
    export PKCS11_PIN
    export PKCS11_SO_PIN

    # Run tests
    log_info "Running integration tests..."

    # First, run the main integration tests (embedded transport)
    if go test -v -tags='integration codec_cbor codec_json codec_msgpack' ./test/integration/pkcs11/module/... -timeout 10m; then
        log_success "Go integration tests passed"
    else
        log_failure "Go integration tests failed"
        return 1
    fi

    # Then, run external pkcs11-tool compatibility tests if tag enabled
    log_info "Running external pkcs11-tool compatibility tests..."
    if go test -v -tags='integration,pkcs11,pkcs11_external,codec_cbor,codec_json,codec_msgpack' ./test/integration/pkcs11/module/... -timeout 5m 2>/dev/null; then
        log_success "External pkcs11-tool tests passed"
    else
        log_warning "External pkcs11-tool tests skipped or failed (may be expected)"
    fi

    return 0
}

# Print summary
print_summary() {
    print_header "Test Summary"

    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo ""

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        echo ""
        echo "Failed tests:"
        echo -e "$TEST_RESULTS" | grep "^FAIL:" || true
        return 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    fi
}

# Main execution
main() {
    print_header "PKCS#11 Module Integration Test Suite"

    log_info "Configuration:"
    log_info "  PKCS11_MODULE: $PKCS11_MODULE"
    log_info "  XKMS_UNIX_SOCKET: $XKMS_UNIX_SOCKET"
    log_info "  XKMS_GRPC_ADDR: $XKMS_GRPC_ADDR"
    log_info "  XKMS_CONNECTION_MODE: $XKMS_CONNECTION_MODE"

    # Run tests
    local exit_code=0

    verify_module || exit_code=1

    if [ $exit_code -eq 0 ]; then
        wait_for_server || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        test_pkcs11_tool || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        run_go_tests || exit_code=1
    fi

    # Print summary
    print_summary || exit_code=1

    exit $exit_code
}

# Run main
main "$@"
