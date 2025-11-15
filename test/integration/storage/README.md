# Storage Integration Tests

Comprehensive integration tests for go-keychain storage packages.

## Overview

This directory contains end-to-end integration tests for all storage implementations:

- **File Storage**: File-based persistent storage with filesystem operations
- **Memory Storage**: In-memory storage with high-performance characteristics
- **Hardware Storage**: Hardware-backed certificate storage for PKCS#11 and TPM2

## Test Coverage

### File Storage (`pkg/storage/file`)
- ✅ Basic CRUD operations (Create, Read, Update, Delete)
- ✅ Multiple keys and nested path structures
- ✅ Concurrent read/write operations (50+ goroutines)
- ✅ File permissions and security
- ✅ Large value handling (10MB+)
- ✅ KeyStorage interface compliance
- ✅ CertificateStorage interface compliance
- ✅ Error handling and edge cases

### Memory Storage (`pkg/storage/memory`)
- ✅ Basic CRUD operations
- ✅ High-volume operations (1000+ keys)
- ✅ Prefix filtering and listing
- ✅ Concurrent access safety (100+ goroutines)
- ✅ Concurrent read/write stress testing
- ✅ Large value handling (50MB+)
- ✅ Data isolation and immutability
- ✅ Memory leak verification
- ✅ KeyStorage interface compliance
- ✅ CertificateStorage interface compliance

### Hardware Storage (`pkg/storage/hardware`)
- ✅ Hybrid storage mode (hardware + external)
- ✅ Automatic fallback on capacity exhaustion
- ✅ Certificate chain support
- ✅ Concurrent hardware operations
- ✅ Capacity reporting and monitoring
- ✅ List and update operations
- ✅ Error handling for hardware errors
- ✅ Closed storage behavior
- ✅ Hybrid list merging
- ✅ Dual-storage delete operations

## Running Tests

### Run All Storage Integration Tests
```bash
make integration-test-storage
```

### Run Specific Storage Tests

#### File Storage Only
```bash
cd test/integration/storage
docker-compose run --rm test-file
```

#### Memory Storage Only
```bash
cd test/integration/storage
docker-compose run --rm test-memory
```

#### Hardware Storage with PKCS#11
```bash
cd test/integration/storage
docker-compose run --rm test-hardware-pkcs11
```

#### Hardware Storage with TPM2
```bash
cd test/integration/storage
docker-compose up -d tpm-simulator
docker-compose run --rm test-hardware-tpm2
docker-compose down
```

### Run Locally (Without Docker)

#### File and Memory Storage
```bash
go test -v -tags=integration ./test/integration/storage/... \
  -run 'TestFileStorage|TestMemoryStorage'
```

#### Hardware Storage (requires SoftHSM or TPM device)
```bash
# With PKCS#11/SoftHSM
export SOFTHSM2_CONF=/path/to/softhsm2.conf
go test -v -tags='integration,pkcs11' ./test/integration/storage/... \
  -run 'TestHardwareStorage'

# With TPM2
export TPM2_SIMULATOR_HOST=localhost
export TPM2_SIMULATOR_PORT=2321
go test -v -tags='integration,tpm2' ./test/integration/storage/... \
  -run 'TestHardwareStorage'
```

## Code Coverage

Generate coverage reports for storage packages:

```bash
# File storage
make coverage-file-storage

# Memory storage
make coverage-memory-storage

# Hardware storage
make coverage-hardware-storage

# All storage packages
make coverage-storage
```

## Test Architecture

### Test Organization
```
test/integration/storage/
├── README.md                                  # This file
├── docker-compose.yml                         # Docker test environment
├── softhsm2.conf                             # SoftHSM configuration
├── file_storage_integration_test.go          # File storage tests
├── memory_storage_integration_test.go        # Memory storage tests
└── hardware_storage_integration_test.go      # Hardware storage tests
```

### Test Patterns

#### Concurrent Safety Testing
All tests include concurrent access patterns to verify thread safety:
- Multiple goroutines performing simultaneous reads
- Multiple goroutines performing simultaneous writes
- Mixed concurrent read/write operations
- Stress testing with 50-100+ concurrent goroutines

#### Error Handling
Comprehensive error case coverage:
- Non-existent key/certificate retrieval
- Invalid input validation
- Closed storage operations
- Hardware capacity limitations
- Concurrent operation conflicts

#### Performance Testing
Tests include performance characteristics:
- Large value handling (10MB - 50MB)
- High-volume operations (1000+ items)
- Sustained concurrent load testing
- Memory leak detection

## Hardware Storage Test Environment

### PKCS#11 (SoftHSM)
The docker-compose environment includes SoftHSM for PKCS#11 testing:
- Pre-initialized token: `test-token`
- SO-PIN: `1234`
- User PIN: `1234`
- Slot: `0`

### TPM2 Simulator
IBM TPM2 simulator provides software TPM for testing:
- Simulated TPM 2.0 device
- Network interface on port 2321
- Full TPM command set support

## Requirements

### Software Dependencies
- Go 1.21+
- Docker & Docker Compose
- Build tools (gcc, make)

### Optional (for local testing)
- SoftHSM2 (for PKCS#11 tests)
- SWTPM (for TPM2 tests)
- TPM2-TSS libraries

## Troubleshooting

### SoftHSM Tests Failing
```bash
# Verify SoftHSM is installed
softhsm2-util --show-slots

# Re-initialize token
softhsm2-util --init-token --slot 0 --label test-token --so-pin 1234 --pin 1234
```

### TPM2 Tests Failing
```bash
# Check TPM simulator is running
docker-compose ps tpm-simulator

# View simulator logs
docker-compose logs tpm-simulator

# Restart simulator
docker-compose restart tpm-simulator
```

### Permission Errors
```bash
# File storage permission issues
chmod 755 test/integration/storage
rm -rf /tmp/go-keychain-test-*

# SoftHSM token directory
sudo mkdir -p /var/lib/softhsm/tokens
sudo chmod 1777 /var/lib/softhsm/tokens
```

## Contributing

When adding new storage implementations or tests:

1. Follow existing test patterns for consistency
2. Ensure 90%+ code coverage
3. Include concurrent access tests
4. Test error handling thoroughly
5. Document any special requirements
6. Update this README with new test cases

## License

Copyright (c) 2025 Jeremy Hahn
SPDX-License-Identifier: AGPL-3.0
