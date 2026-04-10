# Phone/Device E2E Testing

Two levels of E2E testing for the device pairing protocol.

## Go TCP E2E Tests

Tests the full TCP wire protocol: real TCP, Noise XX handshake, encrypted JSON-RPC.

- **Location:** `xkey/test/integration/phone/tcp_e2e_test.go`
- **Build tag:** `integration`
- **Server:** `TCPPhoneServer` wraps `phone.TCPPairingServer` with `MockPhoneRequestHandler`
- **Client:** `tcpE2EClient` performs Noise XX as initiator over real TCP

Tests: Handshake, Ping, GetInfo, GenerateKey, Sign, DeleteKey, LoadKey, SignKeyNotFound, MethodNotFound, MultipleOperations, ConcurrentClients, ClientDisconnectReconnect, AllAlgorithms (ES256/ES384/ES512).

### Run

```bash
cd xkey && make integration-test-phone-tcp
# Or directly:
go test -tags integration -run TestTCPE2E -v ./test/integration/phone/...
```

## Android Emulator E2E Tests

Tests real Go desktop to real Android app using a Docker emulator.

- **Location:** `xkey/test/integration/phone/android_e2e_test.go`
- **Build tag:** `integration,androidemu`
- **Docker:** `budtmo/docker-android:emulator_14.0` with KVM acceleration
- **Infrastructure:** `xkey/test/integration/phone/docker-compose.yml`

### Services

| Service            | Description                    |
|--------------------|--------------------------------|
| `android-emulator` | Android 14 emulator (Pixel 7)  |
| `xkey-desktop`     | TCP relay server               |
| `test-runner`      | Go test runner with ADB        |

### Run

```bash
cd xkey && make integration-test-phone-android
# Requires /dev/kvm for hardware virtualization
```

Full Android E2E tests require the xkey-android app to have a TCP pairing client (`TcpPairingClient.kt`). The current scaffold verifies emulator boot and sets up the test infrastructure.

## Existing Mock Transport Tests

In-process tests using `MockTransport` (bypasses TCP).

- **Location:** `xkey/test/integration/phone/phone_integration_test.go`
- Tests the JSON-RPC protocol and fragmentation without network
