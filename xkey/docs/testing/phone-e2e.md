# Phone/Device E2E Testing

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: how to run the phone pairing E2E tests under `xkey/test/integration/phone`; the targets are in `xkey/Makefile`.

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
```

The target runs `go test -run TestTCPE2E ./test/integration/phone/...` with
`INTEGRATION_TEST_FLAGS`, whose tags are `integration linux tpm_simulator`
plus the Makefile's `BUILD_TAGS` (`xkey/Makefile:155`).
`make integration-test-phone` runs every test in the package.

## Android Emulator E2E Tests

Tests real Go desktop to real Android app using a Docker emulator.

- **Location:** `xkey/test/integration/phone/android_e2e_test.go`
- **Build constraint:** `integration && androidemu`
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

The target runs `docker compose -f test/integration/phone/docker-compose.yml up --build --abort-on-container-exit --exit-code-from test-runner`.

Full Android E2E tests require the xkey-android app to have a TCP pairing client (`TcpPairingClient.kt`). `TestAndroidE2E_EmulatorBoot` verifies the emulator boots. `TestAndroidE2E_TCPPairing` launches the pairing activity but does not yet verify the result (`android_e2e_test.go:58`).

## Existing Mock Transport Tests

In-process tests using `MockTransport` (bypasses TCP).

- **Location:** `xkey/test/integration/phone/phone_integration_test.go`
- Tests the JSON-RPC protocol and fragmentation without network
