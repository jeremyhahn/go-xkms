# BLE Phone Backend Testing

## Unit Tests

### Go Package Tests

Run all phone package tests:

```bash
cd xkey
go test -v ./pkg/phone/
```

Run with coverage:

```bash
go test -cover ./pkg/phone/
```

Run specific test:

```bash
go test -v ./pkg/phone/ -run TestNoiseSession_FullHandshake
```

### Test Files

| File | Coverage |
|------|----------|
| `errors_test.go` | Error definitions, uniqueness |
| `protocol_test.go` | JSON-RPC encoding/decoding |
| `fragmentation_test.go` | Fragment/reassemble round-trip |
| `noise_test.go` | Noise handshake, encryption |
| `phone_test.go` | Backend interface, config |

### Benchmarks

```bash
go test -bench=. ./pkg/phone/
```

Available benchmarks:
- `BenchmarkNoiseHandshake` - Full XX handshake
- `BenchmarkNoiseEncrypt` - Message encryption
- `BenchmarkFragment` - Message fragmentation
- `BenchmarkReassemble` - Fragment reassembly
- `BenchmarkHexEncodeCredentialID` - Credential ID encoding

## Mock-Based Integration Tests

The mock-based integration tests verify the complete protocol flow without requiring BLE hardware. They use a mock phone and mock transport that simulate the Android app's behavior in-process.

### Running Mock Integration Tests

```bash
cd xkey
go test -tags integration -v ./test/integration/phone/...
```

### What's Tested

| Test | Description |
|------|-------------|
| `TestIntegration_Connection` | Noise handshake and connection |
| `TestIntegration_Ping` | Health check / keepalive |
| `TestIntegration_GetInfo` | Device capabilities query |
| `TestIntegration_GenerateKey` | Key generation (ES256) |
| `TestIntegration_GenerateKey_AllAlgorithms` | ES256, ES384, ES512 |
| `TestIntegration_Sign` | Signing operation |
| `TestIntegration_Sign_KeyNotFound` | Error handling |
| `TestIntegration_DeleteKey` | Key deletion |
| `TestIntegration_LoadKey` | Key verification |
| `TestIntegration_MethodNotFound` | Unknown method error |
| `TestIntegration_SmallMTU` | Fragmentation with MinMTU |
| `TestIntegration_MultipleOperations` | Sequential operations |
| `TestIntegration_ReconnectAfterDisconnect` | Session recovery |

### Test Components

```
xkey/test/integration/phone/
├── mock_phone.go         # Simulates Android phone behavior
├── mock_transport.go     # Simulates BLE transport layer
├── tcp_transport.go      # TCP transport (for future server tests)
└── phone_integration_test.go  # Integration test cases
```

## Real Device Integration Testing

### Prerequisites

1. **Android Device**
   - Physical device with BLE and biometric
   - Xkey Android app installed
   - Connected via USB for debugging

2. **Desktop**
   - Linux with BlueZ 5.48+ (or macOS/Windows)
   - Xkey built with BLE: `go build -tags ble ./cmd/xkey/`

### Test Scenarios

#### 1. Pairing Flow

```bash
# On phone: Open Xkey app

# On desktop:
xkey phone pair

# Expected:
# - Phone appears in scan results
# - OS pairing dialog on both devices
# - Noise handshake completes
# - "Paired successfully" message
```

#### 2. Connection Test

```bash
# On phone: Ensure app is running

# On desktop:
xkey phone status

# Expected:
# - Shows paired device
# - Connection status: connected
# - Device info displayed
```

#### 3. Key Generation

```bash
# Start FIDO2 device with phone backend
xkey fido2 --backend phone

# In browser: Navigate to webauthn.io
# Click "Register"

# Expected:
# - Phone shows biometric prompt
# - User authenticates
# - Registration succeeds
```

#### 4. Authentication

```bash
# After registration, click "Authenticate" on webauthn.io

# Expected:
# - Phone shows biometric prompt
# - User authenticates
# - Authentication succeeds
```

#### 5. Error Handling

```bash
# Test biometric cancellation:
# - Start authentication
# - Cancel biometric on phone
# - Verify graceful error on desktop

# Test connection loss:
# - Disable Bluetooth on phone mid-operation
# - Verify timeout and error recovery

# Test invalid credential:
# - Try to sign with non-existent credential ID
# - Verify appropriate error returned
```

### Automated Integration Tests

Integration tests require real BLE hardware and are located in:

```
test/integration/phone/
├── pairing_test.go      # Pairing flow tests
├── operations_test.go   # Key operations tests
└── stress_test.go       # Load and reliability tests
```

Run with:

```bash
# Requires BLE hardware and paired phone
go test -tags "ble,integration" ./test/integration/phone/
```

### WebAuthn End-to-End Test

Full end-to-end test using real WebAuthn:

1. Start Xkey with phone backend:
   ```bash
   xkey fido2 --backend phone
   ```

2. Open Chrome/Firefox and navigate to:
   - https://webauthn.io
   - https://demo.yubico.com/webauthn-technical/registration

3. Complete registration flow:
   - Enter username
   - Click "Register"
   - Authenticate on phone
   - Verify success

4. Complete authentication flow:
   - Click "Authenticate"
   - Authenticate on phone
   - Verify success

### Performance Testing

#### Latency Measurement

```bash
# Measure end-to-end signing latency
xkey phone benchmark --operations 100

# Expected output:
# Operations: 100
# Average latency: ~500ms (biometric) + ~50ms (BLE)
# P99 latency: ~800ms
```

#### Throughput Test

```bash
# Sequential operations without biometric (test mode)
xkey phone benchmark --no-biometric --operations 1000

# Expected: ~20 ops/sec limited by BLE throughput
```

## Debugging

### BLE Debugging (Linux)

```bash
# Monitor BLE traffic
sudo btmon

# Check adapter status
bluetoothctl show

# List paired devices
bluetoothctl paired-devices
```

### Noise Protocol Debugging

Enable verbose logging:

```bash
XKEY_LOG_LEVEL=debug xkey phone pair
```

### Android Debugging

```bash
# View Xkey logs
adb logcat -s Xkey:V

# View BLE logs
adb logcat -s BluetoothGatt:V BluetoothAdapter:V

# Enable BLE HCI snoop log
adb shell settings put global bluetooth_hci_log 1
```

## Test Coverage Goals

| Component | Target | Notes |
|-----------|--------|-------|
| errors.go | 100% | All errors tested |
| protocol.go | 90%+ | All message types |
| fragmentation.go | 90%+ | Edge cases covered |
| noise.go | 85%+ | Handshake + encrypt/decrypt |
| phone.go | 70%+ | Interface + config |
| ble_transport.go | 50%+ | Requires real BLE |

Current coverage: ~46% (stubs reduce overall coverage)

## Known Limitations

1. **BLE transport requires hardware**: Cannot unit test without real BLE adapter
2. **Biometric requires user**: Automated tests need biometric bypass
3. **Android tests require device**: No emulator support for StrongBox
4. **Platform-specific**: BLE behavior varies by OS
