# TPM2 Session Encryption Verification

This document describes the TPM2 session encryption verification tests that use packet capture to validate that sensitive data is properly encrypted during TPM operations.

## Overview

TPM 2.0 supports session-based encryption to protect sensitive data transmitted between the CPU and TPM over the system bus. This is critical for preventing bus snooping attacks and ensuring confidentiality of cryptographic operations.

The integration tests in this project verify session encryption by:

1. **Capturing raw TPM traffic** at the transport layer
2. **Analyzing packet headers** for encryption flags
3. **Detecting sensitive data patterns** that should be encrypted
4. **Comparing encrypted vs unencrypted** sessions

## Architecture

### Packet Capture Infrastructure

The capture infrastructure uses a custom transport wrapper that intercepts all TPM commands and responses:

```go
type TPMCapture struct {
    base    transport.TPMCloser  // Underlying TPM transport
    packets []TPMPacket           // Captured packets
    active  bool                  // Capture enabled/disabled
}
```

#### Key Components

1. **`capture.go`** - Transport wrapper and packet capture logic
   - `TPMCapture`: Wraps go-tpm transport to intercept traffic
   - `TPMPacket`: Represents captured command/response
   - Packet parsing for TPM headers and session areas

2. **`capture_test.go`** - Integration tests for encryption verification
   - `TestTPMSessionEncryption`: Verifies encrypted sessions
   - `TestTPMSessionNoEncryption`: Baseline unencrypted comparison
   - `TestTPMSessionEncryptionComparison`: Side-by-side comparison
   - `TestTPMMultipleOperationsEncryption`: Tests across operations
   - `TestTPMDecryptionEncryption`: Verifies decryption protection

3. **`capture_helper.go`** - Test setup utilities
   - `NewTPM2TestSetup`: Creates test environment with capture
   - `TPM2TestSetup`: Encapsulates test components

## Test Scenarios

### 1. Encrypted Session Test

**Purpose**: Verify that TPM operations use encrypted sessions when configured.

**Test Flow**:
1. Create TPM keystore with `EncryptSession: true`
2. Generate RSA-2048 key (sensitive operation)
3. Capture all TPM traffic during generation
4. Analyze packets for encryption flags
5. Verify no plaintext sensitive data detected

**Expected Results**:
- Session-based commands present (`TPM_ST_SESSIONS`)
- Encryption flags set in session attributes
- Zero plaintext detections
- Encryption rate > 0%

### 2. Unencrypted Session Test

**Purpose**: Establish baseline behavior without encryption for comparison.

**Test Flow**:
1. Create TPM keystore with `EncryptSession: false`
2. Generate RSA-2048 key
3. Capture and analyze traffic
4. Compare encryption metrics to encrypted test

**Expected Results**:
- Lower or zero encryption rate
- Demonstrates difference from encrypted mode

### 3. Multiple Operations Test

**Purpose**: Verify encryption across different TPM operations.

**Operations Tested**:
- Key Generation (`TPM2_Create`)
- Key Loading (`TPM2_Load`)
- Signing (`TPM2_Sign`)
- Decryption (`TPM2_RSA_Decrypt`)

**Validation**: Each operation analyzed independently for encryption.

### 4. Decryption Protection Test

**Purpose**: Ensure decrypted plaintext never appears in TPM traffic.

**Test Flow**:
1. Generate encryption key
2. Encrypt plaintext using public key
3. Decrypt using TPM with session encryption
4. Verify plaintext not in captured packets

## Packet Analysis

### TPM Command Structure

```
┌─────────────────────────────────────┐
│ TPM Command Header (10 bytes)      │
│  - Tag (2):     TPM_ST_SESSIONS     │
│  - Size (4):    Total packet size   │
│  - Code (4):    Command code        │
├─────────────────────────────────────┤
│ Handle Area (variable)              │
├─────────────────────────────────────┤
│ Authorization Area (if sessions)    │
│  - Auth Size (4)                    │
│  - Sessions (variable)              │
│    * Session Handle                 │
│    * Nonce                          │
│    * Session Attributes (1 byte)    │  <-- Encryption flags here
│      - Bit 5 (0x20): Encrypt        │
│      - Bit 6 (0x40): Decrypt        │
│    * HMAC                           │
├─────────────────────────────────────┤
│ Parameters (variable, encrypted)    │
└─────────────────────────────────────┘
```

### Encryption Detection

The analysis looks for:

1. **Session Presence**: `TPM_ST_SESSIONS` tag (0x8002)
2. **Encryption Flags**: Session attributes with bits 5 or 6 set
3. **Plaintext Absence**: No sensitive patterns in packet data

### Metrics Collected

- **Total Packets**: All captured packets
- **Command/Response Split**: Direction analysis
- **Session Commands**: Commands with session area
- **Encrypted Sessions**: Commands with encryption flags
- **Plaintext Detections**: Sensitive data found (should be 0)
- **Encryption Percentage**: Encrypted sessions / Total session commands

## Running the Tests

### Using Make (Recommended)

```bash
# Run encryption tests in Docker
make test-tpm2-encryption

# Run locally (requires TPM simulator or device)
make test-tpm2-encryption-local
```

### Using Docker Compose

```bash
cd test/integration/tpm2

# Start TPM simulator
docker-compose up -d tpm-simulator

# Run encryption tests
docker-compose run --rm test sh /app/test/integration/tpm2/run_capture_tests.sh

# Cleanup
docker-compose down -v
```

### Using Go Test Directly

```bash
# With TPM simulator
export TPM2_SIMULATOR_HOST=localhost
export TPM2_SIMULATOR_PORT=2321

# Run tests
go test -v -tags='integration tpm2' \
    -run 'TestTPMSession' \
    ./test/integration/tpm2/
```

## Test Output

### Successful Encryption Verification

```
=== RUN   TestTPMSessionEncryption
    capture_test.go:25: Generating RSA key with encrypted session...
    capture_test.go:37: Captured 15 TPM packets
    capture_test.go:42: TPM Traffic Analysis:
      Total Packets: 15
      Commands: 8 (Session: 6, Encrypted: 6)
      Responses: 7 (Session: 6)
      Plaintext Detections: 0
      Encryption Rate: 100.0%
    capture_test.go:57: Captured 4 packets during signing
    capture_test.go:60: Signing Operation:
    capture_test.go:61: TPM Traffic Analysis:
      Total Packets: 4
      Commands: 2 (Session: 2, Encrypted: 2)
      Responses: 2 (Session: 2)
      Plaintext Detections: 0
      Encryption Rate: 100.0%
--- PASS: TestTPMSessionEncryption (2.45s)
```

### Comparison Output

```
=== RUN   TestTPMSessionEncryptionComparison
    ENCRYPTED SESSION ANALYSIS:
      Encryption Rate: 100.0%

    UNENCRYPTED SESSION ANALYSIS:
      Encryption Rate: 0.0%

    === COMPARISON ===
    Encrypted Sessions: 6 vs 0
    Encryption Rate: 100.0% vs 0.0%
--- PASS: TestTPMSessionEncryptionComparison (4.12s)
```

## Security Guarantees

### What is Verified

1. ✓ **Session encryption enabled**: Encryption flags present in commands
2. ✓ **Sensitive data protected**: No plaintext key material in traffic
3. ✓ **Consistent encryption**: All sensitive operations encrypted
4. ✓ **Decryption protection**: Decrypted data never in transit

### What is NOT Verified

- **Encryption strength**: Tests don't cryptanalyze AES-128 CFB
- **HMAC integrity**: Not validated (separate from confidentiality)
- **Side-channel resistance**: No timing or power analysis
- **TPM firmware security**: Assumes TPM implementation is correct

## Configuration

### Enabling Session Encryption

In TPM2 backend configuration:

```go
config := &tpm2.Config{
    CN:             "my-keystore",
    SRKHandle:      0x81000001,
    EncryptSession: true,  // Enable encryption
    DevicePath:     "/dev/tpmrm0",
}
```

### Session Encryption Parameters

- **Algorithm**: AES-128 CFB (TPM2_ALG_AES, 128-bit key)
- **Direction**: `EncryptIn` (command parameters encrypted)
- **Session Type**: HMAC session (authenticated but unsalted)
- **Hash Algorithm**: SHA-256 for session key derivation

## Troubleshooting

### No Packets Captured

**Symptom**: Test reports 0 packets captured

**Possible Causes**:
- Capture transport not properly injected
- TPM operations using cached handles
- Test running too fast (no operations performed)

**Solution**: Ensure `NewTPM2TestSetup` is used to create test environment

### False Positive Plaintext Detections

**Symptom**: Plaintext detection count > 0

**Possible Causes**:
- Sensitive pattern too broad (e.g., common byte sequences)
- Legitimate metadata containing pattern
- Encryption not enabled in config

**Solution**: Review sensitive patterns in `getSensitivePatterns()`

### Encryption Rate < 100%

**Symptom**: Some session commands not showing encryption

**Possible Causes**:
- Mixed encrypted/unencrypted operations (some don't need encryption)
- Policy sessions (different encryption rules)
- Public data commands (don't require encryption)

**Expected**: 100% for sensitive operations, may be lower for mixed workloads

## Implementation Details

### Transport Wrapper

The `TPMCapture` struct implements `transport.TPMCloser`:

```go
type TPMCapture struct {
    base    transport.TPMCloser
    packets []TPMPacket
    mu      sync.Mutex
    active  bool
}

func (tc *TPMCapture) Send(cmd []byte) error {
    // Capture command
    if tc.active {
        tc.mu.Lock()
        tc.packets = append(tc.packets, TPMPacket{
            Direction: "send",
            Data:      copy(cmd),
            Timestamp: time.Now(),
        })
        tc.mu.Unlock()
    }
    return tc.base.Send(cmd)
}

func (tc *TPMCapture) Receive() ([]byte, error) {
    resp, err := tc.base.Receive()
    // Capture response
    if tc.active {
        tc.mu.Lock()
        tc.packets = append(tc.packets, TPMPacket{
            Direction: "recv",
            Data:      copy(resp),
            Timestamp: time.Now(),
        })
        tc.mu.Unlock()
    }
    return resp, err
}
```

### Session Attribute Parsing

Session attributes are extracted from the authorization area:

```go
// Session attributes byte (1 byte):
//   Bit 0: continueSession
//   Bit 1-4: Reserved
//   Bit 5: decrypt (0x20)
//   Bit 6: encrypt (0x40)
//   Bit 7: auditExclusive

func hasEncryption(attrs byte) bool {
    return (attrs & 0x60) != 0  // Check bits 5 or 6
}
```

## References

- **TPM 2.0 Specification**: Part 1 Architecture (Sessions)
- **go-tpm Library**: Session encryption implementation
- **NIST SP 800-147B**: BIOS Protection Guidelines (TPM usage)

## Related Tests

- `tpm2_integration_test.go` - General TPM integration tests
- `tpm2_cert_integration_test.go` - Certificate storage tests
- Unit tests in `pkg/tpm2/` - Backend implementation tests


## Maintenance

### Adding New Test Cases

To add new encryption verification tests:

1. Create test function in `capture_test.go`
2. Use `setupTPM2WithCapture(t, encryptSession)` helper
3. Perform TPM operations
4. Call `AnalyzePackets()` on captured traffic
5. Assert encryption metrics

Example:

```go
func TestTPMNewOperation(t *testing.T) {
    ks, capture, cleanup := setupTPM2WithCapture(t, true)
    defer cleanup()

    capture.Clear()

    // Perform TPM operation
    // ...

    packets := capture.GetPackets()
    analysis := AnalyzePackets(packets, getSensitivePatterns())

    assert.Equal(t, 0, analysis.PlaintextDetections)
    assert.Greater(t, analysis.EncryptedSessions, 0)
}
```

### Updating Sensitive Patterns

Modify `getSensitivePatterns()` to add new patterns:

```go
func getSensitivePatterns() [][]byte {
    return [][]byte{
        []byte("BEGIN RSA PRIVATE KEY"),
        []byte("BEGIN PRIVATE KEY"),
        []byte("BEGIN EC PRIVATE KEY"),
        []byte("YOUR_CUSTOM_PATTERN"),
    }
}
```


**Last Updated**: 2025-11-09
**Maintainer**: go-keychain project
**Test Coverage**: Session encryption verification
