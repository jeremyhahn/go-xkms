# BLE Phone Backend Architecture

## System Components

### Desktop (xkey) - BLE Central

The desktop acts as a BLE central (client) that connects to the phone:

```
xkey/pkg/phone/
├── phone.go          # PhoneKeyBackend (implements FIDO2KeyBackend)
├── ble_transport.go  # BLE GATT client (build tag: ble)
├── ble_transport_stub.go  # Stub for non-BLE builds
├── noise.go          # Noise protocol encryption
├── protocol.go       # JSON-RPC message types
├── fragmentation.go  # BLE packet fragmentation
└── errors.go         # Error definitions
```

### Android Phone - BLE Peripheral

The phone acts as a BLE peripheral (server) with a GATT service:

```
xkey-android/app/src/main/kotlin/com/xkey/
├── ble/
│   ├── GattServer.kt       # BLE GATT server
│   ├── Advertiser.kt       # BLE advertising
│   ├── NoiseSession.kt     # Noise protocol
│   └── FragmentReassembler.kt  # Packet reassembly
├── crypto/
│   ├── KeystoreManager.kt  # Android Keystore operations
│   ├── BiometricHelper.kt  # Biometric authentication
│   └── CborEncoder.kt      # COSE key encoding
├── protocol/
│   ├── Messages.kt         # JSON message types
│   └── Handler.kt          # Request dispatcher
└── ui/
    └── MainActivity.kt     # Main UI
```

## BLE GATT Service Structure

```
xkey Signing Service
UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0
├── Control Point
│   UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00001
│   Properties: Write (encrypted)
│   Purpose: Receive requests from desktop
├── Response
│   UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00002
│   Properties: Notify (encrypted)
│   Purpose: Send responses to desktop
└── Status
    UUID: f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d00003
    Properties: Read
    Purpose: Device info and capabilities
```

## Security Layers

The protocol uses two independent encryption layers:

```
┌─────────────────────────────────────┐
│     Application Data (JSON-RPC)     │
├─────────────────────────────────────┤
│     Noise Encryption (Layer 2)      │
│     ChaCha20-Poly1305 + PFS         │
├─────────────────────────────────────┤
│     BLE GATT Fragmentation          │
│     7-byte header per packet        │
├─────────────────────────────────────┤
│     BLE Link Encryption (Layer 1)   │
│     LE Secure Connections           │
└─────────────────────────────────────┘
```

### Layer 1: BLE Link Encryption

Standard BLE security provided by the OS:
- LE Secure Connections (BLE 4.2+)
- ECDH key exchange during pairing
- AES-128-CCM encryption
- Bonding stores keys for reconnection

### Layer 2: Noise Protocol

Application-layer encryption for defense in depth:
- Pattern: `Noise_XX_25519_ChaChaPoly_SHA256`
- Mutual authentication with static keys
- Perfect forward secrecy with ephemeral keys
- Protection against compromised BLE stack

## Noise XX Handshake

The XX pattern provides mutual authentication with identity hiding:

```
Initiator (Desktop)              Responder (Phone)
       |                                |
       |-------- e ------------------>  |  msg1: ephemeral key
       |                                |
       |<------- e, ee, s, es -------   |  msg2: ephemeral, DH, static, DH
       |                                |
       |-------- s, se -------------->  |  msg3: static, DH
       |                                |
       |      [session established]     |
       |                                |
```

After handshake:
- Both parties have authenticated each other's static keys
- Session keys derived for bidirectional encryption
- Ephemeral keys provide forward secrecy

## Data Flow

### Key Generation

```
1. Desktop: WebAuthn site requests credential creation
2. Desktop → Phone: GenerateKey(credentialID, algorithm)
3. Phone: Show biometric prompt
4. User: Authenticates with fingerprint
5. Phone: Generate key in Keystore with biometric binding
6. Phone → Desktop: PublicKey (COSE encoded)
7. Desktop: Return credential to browser
```

### Signing (Authentication)

```
1. Desktop: WebAuthn site requests assertion
2. Desktop → Phone: Sign(credentialID, clientDataHash)
3. Phone: Show biometric prompt with site info
4. User: Authenticates with fingerprint
5. Phone: Sign with Keystore key (unlocked by biometric)
6. Phone → Desktop: Signature (DER encoded)
7. Desktop: Return assertion to browser
```

## Android Keystore Integration

Keys are generated with hardware security:

```kotlin
val keyGenSpec = KeyGenParameterSpec.Builder(
    credentialId,
    PURPOSE_SIGN
)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(DIGEST_SHA256, DIGEST_SHA384, DIGEST_SHA512)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)
    .setIsStrongBoxBacked(true)  // Use hardware security module
    .build()
```

Security properties:
- Keys never leave secure hardware
- Every use requires biometric authentication
- StrongBox provides tamper resistance
- Keys bound to device, cannot be extracted

## Build Tags

The Go implementation uses build tags for optional BLE support:

```go
//go:build ble

// ble_transport.go - Real BLE implementation
```

```go
//go:build !ble

// ble_transport_stub.go - Returns ErrBLEUnavailable
```

Build with BLE:
```bash
go build -tags ble ./cmd/xkey/
```

Build without BLE:
```bash
go build ./cmd/xkey/
```
