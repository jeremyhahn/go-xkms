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

Key types: `NoiseSession`, `NoiseSessionConfig`, `HandshakeConfig`, `StaticKey`

Key functions: `NewNoiseSession`, `PerformHandshake`, `GenerateStaticKey`, `LoadStaticKey`

`StaticKey` holds its private scalar in protected memory — guard-paged, outside
the Go heap, locked against swap, wiped on `Destroy`. Its owner must `Destroy`
it once every session built from it has finished; the session reads those pages
in place, so destroying a key that is still in use frees memory a handshake is
reading. A key passed in through a config stays the caller's to destroy.

`EncodeStaticKey(dst []byte, key *StaticKey) error` writes the hex encoding
into a caller-supplied buffer of at least `NoiseHexKeySize` bytes. There is no
encode-to-string form, because a Go string is immutable and cannot be wiped
after use.

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

### Device attestation, protocol version 2 (#129)

`local.attestDevice` is a **challenge-response** exchange. The device holds one
persistent, hardware-backed **Device Attestation Key** (DAK), generated and
attested once; its `SubjectPublicKeyInfo` hashes to the stable
`DeviceFingerprint`. Freshness is a live signature over the verifier's nonce,
not a nonce embedded in the attestation certificate — the two are mutually
exclusive on Android, where Keystore fixes the attestation challenge at key
generation.

Request (`LocalAttestDeviceParams`) carries `protocolVersion: 2`, the 32-byte
`nonce` and the `purpose` (`pair` | `reattest`). Response
(`LocalAttestDeviceResult`) adds `certificateChain`, `signature` and
`signatureAlgorithm: "ES256"`.

**The request deliberately carries no channel binding.** The transcript commits
to one, and each side derives it from its own session. Sending it would make a
prover that signs the value it was handed byte-indistinguishable from one that
derived its own — right up until the relay attack the binding exists to stop, at
which point the relayed signature verifies. A field whose only safe handling is
"never use it" is a footgun, not a diagnostic. Each side logs its own derived
value at debug level instead.

Signed transcript (`pairing.BuildAttestTranscript`):

```
"xkey-attest-transcript-v1" || len8(purpose) || purpose
                            || nonce(32) || channelBinding(32) || fingerprint(32)
```

Channel binding (`pairing.ComputeAttestChannelBinding`):

```
SHA-256( "xkey-attest-channel-v1"
       || 0x20 || initiatorStaticPub(32)
       || 0x20 || responderStaticPub(32)
       || len8(prologue) || prologue )
```

The DAK's genesis attestation challenge must begin with
`xkey-device-attestation-v1`.

**Downgrade is refused symmetrically.** A version 2 challenge answered with any
other version is refused by the verifier (`ErrAttestProtocolDowngrade`); a
request that does not ask under version 2 is refused by the prover with
`ErrorCodeAttestProtocolDowngrade` (**-32037**). Either side accommodating the
older model would let the party being checked choose which checks apply to it.
go-xkms never sends -32037 — this repository is the verifier — but the code is
reserved here so a future method family cannot claim it.

### Interop vectors

Published on go-xkms#129 and pinned in `xkey/pkg/pairing/attest_vectors_test.go`.
A change to any of them is a wire break, not an edit.

Note the **role-reversed** channel-binding vector (initiator `0x22`, responder
`0x11`). It exists because the other two cannot catch a role-blind derivation on
their own: in them the initiator (`0x11`) already sorts before the responder
(`0x22`), so a derivation that sorted the keys — or hashed "mine then theirs" —
reproduces them exactly. The real-path interop test does not catch it either,
since both ends call the same derivation and a mutation moves the oracle with
the subject. Measured. A vector set that cannot catch role-blindness is an
incomplete contract for the next implementer.

Full rationale and threat model:
[../phone-hsm/engineering.md](../phone-hsm/engineering.md#challenge-response-attestation-129).

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

## Paired device record

`pairing.PairedDevice` (`xkey/pkg/pairing/device.go`) is the one persisted
record for a paired device: the CLI's `devices.yaml` and the GUI's mirror of
the same file both read and write it directly (#130). It records the device
name, address, Noise static keys, attestation fields (security level, boot
state, device fingerprint, protocol version) and timestamps — see
[Unified Device Pairing](README.md#configuration) for the on-disk shape.

An earlier, unimplemented design sketch had `pairing.DeviceType`,
`pairing.EnrollmentMethod`, `pairing.TransportType` and a separate
`pairing.AttestationPolicy` (`RequireTPM`/`RequireSecureBoot`/…) alongside it;
none were ever constructed or enforced anywhere in the codebase, and they were
removed rather than left as dead exports. Device-type discrimination in
practice is per-package: `xkey/pkg/agent` owns agent enrollment (with its own
real `EnrollmentMethod`), and the pairing record above is phone-only.

## Usage Example

```go
// Generate a static key for this device. The key must outlive the session.
staticKey, _ := pairing.GenerateStaticKey()
defer staticKey.Destroy()

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
