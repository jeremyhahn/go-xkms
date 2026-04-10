# Pairing Framework

The `pairing` package provides a generic device pairing protocol for xKey. It implements the Noise XX handshake, bidirectional JSON-RPC 2.0 message routing, transport abstractions, attestation, and bridge routing to xkmsd backends. Both phone and agent device types reuse this package.

## Architecture

```
+----------------+                              +----------------+
|   Desktop/     |   Noise XX (ChaCha20-Poly1305)   |   Remote       |
|   Laptop       |<------- Encrypted Channel ------>|   Device       |
|                |                              |   (Phone/Agent)|
|  +-----------+ |   local.*    +-----------+   | +-----------+  |
|  | Bridge    |<------------- | Message   |   | | Android   |  |
|  | (xkmsd)   | ------------->| Router    |   | | Keystore  |  |
|  +-----------+ |   remote.*  +-----------+   | +-----------+  |
|                |                |             |                |
|  +-----------+ |          +----+----+        |                |
|  | Laptop    | |          |Transport|        |                |
|  | Attestor  | |          | (BLE/TCP)|       |                |
|  +-----------+ |          +---------+        |                |
+----------------+                              +----------------+
```

**Protocol directions:**

- `local.*` methods: Desktop sends TO remote device (operates on device keystore)
- `remote.*` methods: Device sends TO desktop (operates on xkmsd backends)

Both directions share the same Noise-encrypted channel via the `MessageRouter`.

## Noise Protocol Integration

The package uses Noise XX (`Noise_XX_25519_ChaChaPoly_SHA256`) for mutual authentication with Curve25519 key exchange and ChaCha20-Poly1305 encryption.

**Handshake flow with identity exchange:**

1. Initiator sends its static public key to the responder (pre-handshake)
2. Responder replies with device fingerprint (known) or new-device indicator
3. Both sides compute a prologue: `SHA256(public_key || fingerprint || "xkey-v1")`
4. Standard Noise XX 3-message handshake proceeds with prologue binding
5. Post-handshake: encrypted bidirectional channel is established

Key types: `NoiseSession`, `NoiseSessionConfig`, `HandshakeConfig`

Key functions: `NewNoiseSession`, `PerformHandshake`, `GenerateStaticKey`, `LoadStaticKey`

## Transport Layer

The `Transport` interface abstracts communication between paired devices:

```go
type Transport interface {
    Send(ctx context.Context, message []byte) error
    Receive(ctx context.Context) ([]byte, error)
    SendAndReceive(ctx context.Context, message []byte) ([]byte, error)
    IsConnected() bool
    Close() error
}
```

Built-in implementations:

| Transport | Use Case | Framing |
|-----------|----------|---------|
| `TCPTransport` | USB/ADB forwarded connections | 2-byte big-endian length prefix |
| BLE (external) | Bluetooth Low Energy via GATT | Fragmentation with `Fragmenter` |

The `Fragmenter` and `Reassembler` types handle BLE MTU-constrained message splitting with a 7-byte header (flags, sequence, total, length).

## Message Router

`MessageRouter` runs a background receive loop that demultiplexes incoming Noise-decrypted messages into:

- **Responses** -- matched to pending outbound requests by ID
- **Inbound requests** -- dispatched to a `RequestHandler`
- **Notifications** -- fire-and-forget messages (e.g., `local.biometricPending`)

The router is safe for concurrent use. Outbound requests register a buffered channel keyed by request ID; the receive loop delivers matching responses.

## Attestation

The package supports bidirectional device attestation:

| Mode | Description |
|------|-------------|
| `tpm2` | TPM2 quote with PCR values, EK/IAK certificates |
| `software` | Software-only attestation (no hardware proof) |
| `auto` | Uses TPM2 if available, falls back to software |

The `LaptopAttestor` interface generates attestation for the desktop side. Remote devices (phones) provide Android Key Attestation via the `local.attestDevice` method.

TCG-CSR-IDEVID enrollment is supported through `remote.getTCGCSRIDevID`, `remote.activateCredential`, and `remote.getAttestationQuote` methods.

## Bridge

The `Bridge` routes `remote.*` requests from a paired device to xkmsd via the Go SDK `transport.Client`. It provides:

- **O(1) dispatch** -- map-based handler routing for all remote methods
- **Access control** -- allow/deny lists for backend access with O(1) lookups
- **Audit logging** -- optional logging of crypto and key operations
- **Type translation** -- converts between pairing protocol types and SDK types

Supported operations: list backends, list/generate/delete keys, sign, verify, encrypt, decrypt, ECDH key agreement, key/device attestation, backup/restore, OATH sync, PIV operations, trust store sync.

## Sharing Policy

`SharingPolicyStore` manages per-key sharing policies with default-deny semantics:

```go
type SharingPolicy struct {
    KeyID          string   // Key identifier
    Backend        string   // Backend name
    AllowShare     bool     // Must be true to allow any sharing
    SharePublic    bool     // Allow public key export
    SharePrivate   bool     // Allow private key export
    ShareSymmetric bool     // Allow symmetric key export
    AllowedDevices []string // Device fingerprint allowlist
}
```

`FileSharingPolicyStore` provides JSON file persistence. When `AllowedDevices` is set, the requesting device fingerprint must match.

## Device Types

```go
const (
    DeviceTypePhone DeviceType = "phone"  // Android/iOS via BLE or USB
    DeviceTypeAgent DeviceType = "agent"  // Remote agent via TCP/network
    DeviceTypeUSB   DeviceType = "usb"    // USB-connected hardware
)
```

`PairedDevice` records the device name, Noise static public key, attestation data, security level, and timestamps. `AttestationPolicy` defines requirements such as `RequireTPM`, `RequireSecureBoot`, and `MinSecurityLevel`.

## Usage Example

```go
// Generate a static key for this device
staticKey, _ := pairing.GenerateStaticKey()

// Create a Noise session as initiator
session, _ := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
    LocalStaticKey: staticKey,
    IsInitiator:    true,
})

// Connect via TCP (ADB-forwarded)
transport, _ := pairing.NewTCPTransport(&pairing.TCPTransportConfig{
    Address: "localhost:8444",
})
transport.Connect(ctx)

// Perform the Noise handshake
pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
    Transport:            transport,
    Session:              session,
    LocalStaticPublicKey: staticKey.Public,
})

// Create a message router for bidirectional communication
router := pairing.NewMessageRouter(transport, session, bridge, logger)
router.Start()
defer router.Stop()

// Send a request to the remote device
req := pairing.NewRequest("local.listKeys", &pairing.LocalListKeysParams{})
resp, _ := router.SendRequest(ctx, req)
```

## See Also

- [Phone Integration](phone/README.md) -- Phone-specific pairing and protocol details
- [BLE Documentation](ble/README.md) -- BLE transport layer
- [Architecture](architecture.md) -- Overall xkey component design
