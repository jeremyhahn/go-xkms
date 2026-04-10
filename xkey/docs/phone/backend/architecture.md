# Phone Backend Architecture

## Overview

The phone backend is a xkmsd backend that delegates all cryptographic operations to an Android phone connected via BLE or USB. It implements the full `types.Backend` interface hierarchy, making the phone a first-class xkmsd backend alongside TPM2, PKCS#11, and software backends.

The Android phone's hardware-backed Keystore (TEE/StrongBox) serves as the cryptographic engine, with biometric authentication gating access to key material. All communication between the laptop and phone is encrypted using the Noise XX protocol, ensuring mutual authentication and forward secrecy.

```
+-----------------------------------------------------------------------+
|                        xkmsd Server                               |
|                    (API: REST, gRPC, QUIC, MCP, Unix)                 |
+-----------------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------------+
|                       Phone Backend                                   |
|                   pkg/backend/phone                                   |
+-----------------------------------------------------------------------+
|  Backend     | Attestation | Symmetric  | KeyAgreement | ImportExport |
|  (core ops)  | (Android KA)| (AES-GCM)  | (ECDH)       | (pub only)   |
+--------------+-------------+------------+--------------+--------------+
                                |
                                v (JSON-RPC over Noise XX)
+-----------------------------------------------------------------------+
|                      Transport Layer                                  |
|              BLE (GATT)  |  TCP (ADB port forward)                    |
+-----------------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------------+
|                       Android Phone                                   |
|  +-----------------------------+  +--------------------------------+  |
|  | Biometric Authentication    |  | Android Keystore               |  |
|  | (Fingerprint / Face)        |  | (TEE / StrongBox)              |  |
|  +-----------------------------+  +--------------------------------+  |
+-----------------------------------------------------------------------+
```

## Package Structure

```
pkg/backend/phone/
+-- backend.go           # types.Backend implementation (core key ops)
+-- attestation.go       # types.AttestingBackend (Android Key Attestation)
+-- config.go            # Backend configuration
+-- connection.go        # Transport abstraction (BLE or TCP for ADB)
+-- errors.go            # Typed errors
+-- signer.go            # crypto.Signer proxy to phone
+-- decrypter.go         # crypto.Decrypter proxy to phone
+-- symmetric.go         # types.SymmetricBackend implementation
+-- key_agreement.go     # types.KeyAgreementBackend (ECDH)
+-- import_export.go     # ImportExportBackend (public key export only)
+-- doc.go               # Package documentation
+-- backend_test.go      # Tests
```

## Component Architecture

```
+-----------------------------------------------------------------------+
|                          xkmsd                                     |
|                                                                       |
|  REST/gRPC/QUIC/MCP/Unix API                                         |
|         |                                                             |
|         v                                                             |
|  +---------------------------+                                        |
|  |    xKMS Service       |                                        |
|  |    (pkg/xkms)         |                                        |
|  +---------------------------+                                        |
|         |                                                             |
|         v                                                             |
|  +---------------------------+     +------------------------------+   |
|  |    Phone Backend          |     |   Other Backends             |   |
|  |    (pkg/backend/phone)    |     |   (TPM2, PKCS#11, Software) |   |
|  +---------------------------+     +------------------------------+   |
|         |                                                             |
|         | crypto.Signer / crypto.Decrypter proxies                    |
|         v                                                             |
|  +---------------------------+                                        |
|  |    JSON-RPC Encoder       |                                        |
|  |    (method + params)      |                                        |
|  +---------------------------+                                        |
|         |                                                             |
|         v                                                             |
|  +---------------------------+                                        |
|  |    Noise XX Session       |                                        |
|  |    (encrypt/decrypt)      |                                        |
|  +---------------------------+                                        |
|         |                                                             |
|         v                                                             |
|  +---------------------------+                                        |
|  |    Transport              |                                        |
|  |    BLE (GATT) | TCP (ADB) |                                        |
|  +---------------------------+                                        |
+-----------------------------------------------------------------------+
              |
              | BLE radio / USB cable
              v
+-----------------------------------------------------------------------+
|                         Android Phone                                 |
|                                                                       |
|  +---------------------------+                                        |
|  |    Transport              |                                        |
|  |    BLE (GATT) | TCP       |                                        |
|  +---------------------------+                                        |
|         |                                                             |
|         v                                                             |
|  +---------------------------+                                        |
|  |    Noise XX Session       |                                        |
|  |    (decrypt/encrypt)      |                                        |
|  +---------------------------+                                        |
|         |                                                             |
|         v                                                             |
|  +---------------------------+                                        |
|  |    JSON-RPC Dispatcher    |                                        |
|  |    local.* | remote.*     |                                        |
|  +---------------------------+                                        |
|         |                   |                                         |
|         v                   v                                         |
|  +--------------+    +------------------+                             |
|  | Biometric    |    | Android Keystore |                             |
|  | Prompt       |    | (TEE/StrongBox)  |                             |
|  +--------------+    +------------------+                             |
+-----------------------------------------------------------------------+
```

## Backend Interface Hierarchy

The phone backend implements the following `types.Backend` interface hierarchy:

| Interface | Purpose | Phone Implementation |
|-----------|---------|---------------------|
| `Backend` | Core key operations: generate, sign, verify, encrypt, decrypt | JSON-RPC `local.generateKey`, `local.sign`, `local.verify`, `local.encrypt`, `local.decrypt` dispatched to Android Keystore |
| `AttestingBackend` | Hardware key attestation | Android Key Attestation: X.509 certificate chain rooted at Google hardware attestation root CA |
| `SymmetricBackend` | Symmetric key generation and AEAD encryption | AES-GCM via Android Keystore `local.symmetricEncrypt` / `local.symmetricDecrypt` |
| `KeyAgreementBackend` | ECDH key agreement | `local.ecdh` delegates to Android Keystore EC key agreement |
| `ImportExportBackend` | Key import/export | Public key export only; private keys are hardware-bound in TEE/StrongBox and cannot be extracted |

### Interface Constraints

```
types.Backend (required)
    |
    +-- types.AttestingBackend
    |   Android Key Attestation only (not custom attestation)
    |   Cert chain: leaf -> intermediate -> Google root
    |
    +-- types.SymmetricBackend
    |   AES-256-GCM only (Android Keystore constraint)
    |   Keys never leave TEE/StrongBox
    |
    +-- types.KeyAgreementBackend
    |   ECDH P-256 / P-384
    |   Raw shared secret stays on phone; derived key returned
    |
    +-- ImportExportBackend
        ExportPublicKey: supported
        ExportPrivateKey: ErrExportNotSupported (hardware-bound)
        ImportKey: ErrImportNotSupported (generate on device)
```

## Transport Layer

The transport layer provides an abstraction over the physical connection between the laptop and phone. Both transport types expose the same `Connection` interface, ensuring the upper layers are transport-agnostic.

### Transport Interface

```go
type Connection interface {
    // Send transmits a message to the phone.
    Send(ctx context.Context, data []byte) error

    // Receive reads a message from the phone.
    Receive(ctx context.Context) ([]byte, error)

    // Close terminates the connection.
    Close() error
}
```

### BLE Transport

BLE uses GATT (Generic Attribute Profile) characteristics for bidirectional communication.

```
Laptop (Central)                    Phone (Peripheral)
     |                                    |
     |--- BLE Scan for service UUID ----->|
     |<-- Advertisement ------------------|
     |                                    |
     |--- Connect ----------------------->|
     |<-- Connection established ---------|
     |                                    |
     |--- Write to TX characteristic ---->|  (request)
     |    [fragmented if > MTU]           |
     |                                    |
     |<-- Notify on RX characteristic ----|  (response)
     |    [reassembled from fragments]    |
```

Key characteristics:
- **Service UUID**: Custom 128-bit UUID identifying the phone backend service
- **TX Characteristic**: Laptop writes request data (supports fragmentation)
- **RX Characteristic**: Phone notifies with response data (supports reassembly)
- **MTU negotiation**: Requests largest supported MTU to minimize fragmentation
- **Fragmentation**: Messages larger than (MTU - 3) bytes are split into chunks with sequence headers

### TCP Transport (ADB)

TCP transport uses Android Debug Bridge (ADB) port forwarding for USB-connected phones.

```
Laptop                    ADB                    Phone
  |                        |                       |
  |-- adb forward -------->|                       |
  |   tcp:PORT -> tcp:PORT |                       |
  |                        |                       |
  |-- TCP connect -------->|--- USB forward ------>|
  |<-- TCP established ----|<-- Established -------|
  |                        |                       |
  |-- Send (raw TCP) ----->|--- Forward ---------->|
  |<-- Receive ------------|<-- Forward -----------|
```

Key characteristics:
- **Stage 1**: ADB port forwarding over USB (requires `adb` binary)
- **Stage 2**: Custom USB driver (future, eliminates ADB dependency)
- **No fragmentation needed**: TCP handles message framing natively
- **Lower latency**: USB provides higher bandwidth than BLE

### Transport Comparison

| Property | BLE | TCP (ADB) |
|----------|-----|-----------|
| Physical medium | Bluetooth radio | USB cable |
| Range | ~10m | Cable length |
| Bandwidth | ~1 Mbit/s | USB speed |
| Latency | 10-50ms | 1-5ms |
| Fragmentation | Required (MTU limited) | Not needed |
| Setup | Automatic scan | `adb forward` command |
| Dependencies | BLE adapter | ADB binary, USB cable |

## Noise Protocol Integration

All communication between the laptop and phone is encrypted using the Noise Protocol Framework with the XX handshake pattern.

### XX Handshake Pattern

The XX pattern provides mutual authentication: both sides prove possession of their static keys.

```
Initiator (Laptop)                        Responder (Phone)
     |                                         |
     |  e -->                                  |
     |  (ephemeral public key)                 |
     |-----------------------------------------|
     |                                         |
     |                              <-- e, ee, s, es
     |  (ephemeral + static keys, encrypted)   |
     |-----------------------------------------|
     |                                         |
     |  s, se -->                              |
     |  (static key, encrypted)                |
     |-----------------------------------------|
     |                                         |
     |  [Transport session established]        |
     |  [Both sides authenticated]             |
```

### Key Management

- **Static keys**: Generated during `xkey phone pair` and stored in config
- **Ephemeral keys**: Generated fresh per connection for forward secrecy
- **Session keys**: Derived from Noise handshake, used for transport encryption
- **Key rotation**: New session keys on every reconnection

### Pairing Flow

```
xkey phone pair
     |
     +-- Generate laptop static keypair
     +-- Display laptop public key (QR code or base64)
     +-- Scan/enter phone public key
     +-- Store both keys in config file
     +-- Perform trial Noise XX handshake to verify
```

### Message Encryption

After the Noise XX handshake completes, every JSON-RPC message is encrypted:

```
Plaintext JSON-RPC          Noise Transport           Encrypted Wire Format
+------------------+        +------------------+      +------------------+
| {"jsonrpc":"2.0",| -----> | Encrypt with     | ---> | [length][nonce]  |
|  "method":"local.|        | ChaChaPoly1305   |      | [ciphertext]     |
|  sign", ...}     |        | session key      |      | [auth tag]       |
+------------------+        +------------------+      +------------------+
```

## Key Operation Flow

### Sign Operation (Typical Flow)

```
xkmsd                Phone Backend           Transport/Noise        Phone
    |                         |                       |                    |
    | Sign(keyAttrs, digest)  |                       |                    |
    |------------------------>|                       |                    |
    |                         |                       |                    |
    |                         | JSON-RPC request:     |                    |
    |                         | local.sign            |                    |
    |                         |---------------------->|                    |
    |                         |                       | encrypt + send     |
    |                         |                       |------------------>|
    |                         |                       |                    |
    |                         |                       |                    | prompt
    |                         |                       |                    | biometric
    |                         |                       |                    |
    |                         |                       |                    | user
    |                         |                       |                    | authenticates
    |                         |                       |                    |
    |                         |                       |                    | Android Keystore
    |                         |                       |                    | signs in TEE
    |                         |                       |                    |
    |                         |                       |  <-- encrypted     |
    |                         |                       |      response      |
    |                         | <-- JSON-RPC response |                    |
    |                         |     (signature bytes) |                    |
    |                         |                       |                    |
    | <-- signature           |                       |                    |
    |                         |                       |                    |
```

### Key Generation Flow

```
xkmsd                Phone Backend           Phone (Android Keystore)
    |                         |                       |
    | GenerateKey(attrs)      |                       |
    |------------------------>|                       |
    |                         | local.generateKey     |
    |                         |---------------------->|
    |                         |                       | generate in TEE
    |                         |                       | (biometric-bound)
    |                         | <-- keyID + pubKey    |
    |                         |                       |
    | <-- KeyAttributes       |                       |
    |    (keyID, algorithm,   |                       |
    |     public key)         |                       |
```

### Attestation Flow

```
xkmsd                Phone Backend           Phone (Android Keystore)
    |                         |                       |
    | AttestKey(keyAttrs)     |                       |
    |------------------------>|                       |
    |                         | local.attestKey       |
    |                         |---------------------->|
    |                         |                       | retrieve attestation
    |                         |                       | cert chain from TEE
    |                         | <-- X.509 cert chain  |
    |                         |                       |
    |                         | verify chain against  |
    |                         | Google root CA        |
    |                         |                       |
    | <-- AttestationResult   |                       |
    |    (cert chain,         |                       |
    |     verified: true)     |                       |
```

## Bidirectional Architecture

The phone backend supports bidirectional cryptographic operations over the same encrypted channel. This enables two distinct use cases:

### Direction 1: local.* (Laptop uses Phone)

The laptop delegates cryptographic operations to the phone's Android Keystore.

```
Laptop (xkmsd)                        Phone (Android Keystore)
     |                                         |
     |  local.generateKey ------------------>  |  TEE generates key
     |  local.sign ------------------------->  |  TEE signs with biometric
     |  local.encrypt ---------------------->  |  TEE encrypts (AES-GCM)
     |  local.decrypt ---------------------->  |  TEE decrypts (AES-GCM)
     |  local.ecdh ------------------------->  |  TEE performs ECDH
     |  local.attestKey -------------------->  |  TEE returns attestation
     |  local.symmetricEncrypt ------------->  |  TEE AES-GCM encrypt
     |  local.symmetricDecrypt ------------->  |  TEE AES-GCM decrypt
```

### Direction 2: remote.* (Phone uses Laptop)

The phone delegates cryptographic operations to the laptop's xkmsd backends (TPM2, PKCS#11, software, cloud KMS).

```
Phone (Android App)                       Laptop (xkmsd)
     |                                         |
     |  remote.generateKey ------------------>  |  TPM2/PKCS#11 generates key
     |  remote.sign ------------------------->  |  TPM2/PKCS#11 signs
     |  remote.encrypt ---------------------->  |  Backend encrypts
     |  remote.decrypt ---------------------->  |  Backend decrypts
     |  remote.listKeys --------------------->  |  List available keys
```

### Bridge Architecture

The Go binary on the laptop acts as a bridge for `remote.*` requests, routing them through the standard xkmsd service layer:

```
Phone App                    Phone Backend (Go)            xkmsd Service
     |                            |                              |
     | remote.sign ------------>  |                              |
     |                            | route to backend ----------> |
     |                            |                              | TPM2.Sign()
     |                            |                              |   or
     |                            |                              | PKCS11.Sign()
     |                            | <-- signature --------------|
     | <-- signature              |                              |
```

## Connection Lifecycle

```
                     +-------------------+
                     |   Uninitialized   |
                     +-------------------+
                              |
                              | Backend.Init(config)
                              | Load static keys from config
                              v
                     +-------------------+
                     |   Initialized     |
                     +-------------------+
                              |
                              | Connect()
                              | BLE scan or TCP connect
                              v
                     +-------------------+
                     |   Connecting      |
                     +-------------------+
                              |
                              | Noise XX handshake
                              | Mutual authentication
                              v
                     +-------------------+
                     |   Authenticated   |
                     +-------------------+
                              |
                              | Session established
                              | JSON-RPC ready
                              v
                     +-------------------+
            +------->   Connected       |<------+
            |        +-------------------+       |
            |                 |                  |
            |     Operations: |                  |
            |     generateKey |                  |
            |     sign        |                  |
            |     encrypt     |  Reconnect on    |
            |     decrypt     |  transient error |
            |     ecdh        |                  |
            |                 |                  |
            +-----------------+------------------+
                              |
                              | Close() or fatal error
                              v
                     +-------------------+
                     |   Disconnected    |
                     +-------------------+
```

### Reconnection Strategy

- **Transient errors** (BLE signal loss, timeout): Automatic reconnect with exponential backoff
- **Authentication errors** (Noise handshake failure): Fail immediately, require re-pairing
- **Fatal errors** (backend closed): No reconnect, return error to caller

## JSON-RPC Protocol

All operations use JSON-RPC 2.0 over the Noise-encrypted transport.

### Request Format

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "local.sign",
    "params": {
        "key_id": "a1b2c3d4",
        "algorithm": "ECDSA-P256-SHA256",
        "digest": "<base64-encoded-digest>"
    }
}
```

### Response Format

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "signature": "<base64-encoded-signature>"
    }
}
```

### Error Response Format

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": -32001,
        "message": "biometric_failed",
        "data": {
            "reason": "user_cancelled"
        }
    }
}
```

### Method Catalog

| Direction | Method | Description |
|-----------|--------|-------------|
| `local` | `local.generateKey` | Generate key in Android Keystore |
| `local` | `local.sign` | Sign digest with TEE-held key |
| `local` | `local.verify` | Verify signature on phone |
| `local` | `local.encrypt` | Asymmetric encrypt (RSA-OAEP) |
| `local` | `local.decrypt` | Asymmetric decrypt (RSA-OAEP) |
| `local` | `local.symmetricEncrypt` | AES-GCM encrypt |
| `local` | `local.symmetricDecrypt` | AES-GCM decrypt |
| `local` | `local.ecdh` | ECDH key agreement |
| `local` | `local.attestKey` | Android Key Attestation |
| `local` | `local.deleteKey` | Delete key from Keystore |
| `local` | `local.listKeys` | List available keys |
| `local` | `local.getPublicKey` | Export public key |
| `remote` | `remote.generateKey` | Generate key on laptop backend |
| `remote` | `remote.sign` | Sign using laptop backend |
| `remote` | `remote.encrypt` | Encrypt using laptop backend |
| `remote` | `remote.decrypt` | Decrypt using laptop backend |
| `remote` | `remote.listKeys` | List laptop backend keys |

## Error Handling

All errors are typed and defined in `errors.go`. Errors are categorized by source.

### Error Categories

| Category | Error Type | Description |
|----------|-----------|-------------|
| Transport | `ErrConnectionLost` | BLE/TCP connection dropped |
| Transport | `ErrConnectionTimeout` | Connection attempt timed out |
| Transport | `ErrBLEUnavailable` | BLE adapter not found or disabled |
| Transport | `ErrADBNotFound` | ADB binary not available for TCP transport |
| Transport | `ErrPhoneNotFound` | Phone not discovered during BLE scan |
| Protocol | `ErrInvalidResponse` | Malformed JSON-RPC response |
| Protocol | `ErrMethodNotFound` | Unsupported JSON-RPC method |
| Protocol | `ErrHandshakeFailed` | Noise XX handshake failed |
| Protocol | `ErrNotPaired` | No stored static keys for phone |
| Phone | `ErrBiometricFailed` | Biometric authentication failed |
| Phone | `ErrUserCancelled` | User declined biometric prompt |
| Phone | `ErrKeyNotFound` | Requested key not in Android Keystore |
| Phone | `ErrKeystoreUnavailable` | Android Keystore service unavailable |
| Phone | `ErrStrongBoxUnavailable` | StrongBox not available on device |
| Backend | `ErrExportNotSupported` | Private key export not allowed |
| Backend | `ErrImportNotSupported` | Key import not supported |
| Backend | `ErrNotConnected` | Operation attempted without connection |

### Error Classification

```go
// IsRetryable returns true for transient errors that may succeed on retry.
func IsRetryable(err error) bool

// IsTransportError returns true for connection-level errors.
func IsTransportError(err error) bool

// IsProtocolError returns true for JSON-RPC and Noise protocol errors.
func IsProtocolError(err error) bool

// IsPhoneError returns true for errors originating from the Android device.
func IsPhoneError(err error) bool

// IsAuthenticationError returns true for biometric/PIN authentication errors.
func IsAuthenticationError(err error) bool
```

### Error Mapping (JSON-RPC to Go)

| JSON-RPC Code | Go Error Type |
|---------------|---------------|
| -32001 | `ErrBiometricFailed` |
| -32002 | `ErrUserCancelled` |
| -32003 | `ErrKeyNotFound` |
| -32004 | `ErrKeystoreUnavailable` |
| -32601 | `ErrMethodNotFound` |
| -32700 | `ErrInvalidResponse` |

## Security Model

### Trust Boundaries

```
+---------------------------+     +---------------------------+
|   Laptop Trust Domain     |     |   Phone Trust Domain      |
|                           |     |                           |
|  xkmsd process        |     |  Android App (user space) |
|  Noise static keys        |     |  Noise static keys        |
|  Backend routing          |     |  Biometric gating         |
|                           |     |  Android Keystore (TEE)   |
+---------------------------+     +---------------------------+
            |                                   |
            +------- Noise XX channel ----------+
            (encrypted, mutually authenticated)
```

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | Noise XX transport encryption (ChaChaPoly1305) |
| Integrity | Noise AEAD authentication tags |
| Mutual authentication | Static key verification during XX handshake |
| Forward secrecy | Ephemeral keys per connection |
| Key binding | Android Keystore TEE/StrongBox hardware binding |
| User presence | Biometric prompt before key operations |
| Attestation | Android Key Attestation with Google root CA |
| Replay protection | Noise nonce counter (monotonic, per session) |

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| BLE eavesdropping | Noise XX encryption (independent of BLE pairing) |
| Man-in-the-middle | Static key pinning from initial pairing |
| Key extraction | Hardware-bound keys in TEE/StrongBox |
| Unauthorized signing | Biometric authentication per operation |
| Replay attacks | Noise nonce counter + session uniqueness |
| Lost phone | Keys require biometric; remote wipe via Android |

## Capabilities

```go
Capabilities: types.Capabilities{
    Keys:                true,   // Key generation and storage
    HardwareBacked:      true,   // TEE/StrongBox backed
    Signing:             true,   // ECDSA, RSA signing
    Decryption:          true,   // RSA-OAEP decryption
    SymmetricEncryption: true,   // AES-256-GCM
    Sealing:             false,  // Not supported
    Import:              false,  // Keys generated on device only
    Export:              false,  // Private keys hardware-bound
    KeyAgreement:        true,   // ECDH P-256, P-384
    Attestation:         true,   // Android Key Attestation
}
```

### Supported Algorithms

| Algorithm | Type | Android Keystore Support |
|-----------|------|-------------------------|
| ECDSA P-256 | Signing | All devices |
| ECDSA P-384 | Signing | Most devices |
| RSA 2048 | Signing, Encryption | All devices |
| RSA 4096 | Signing, Encryption | Most devices |
| AES-256-GCM | Symmetric | All devices |
| ECDH P-256 | Key Agreement | All devices |
| ECDH P-384 | Key Agreement | Most devices |

## See Also

- [Backend Selection Guide](../README.md)
- [Configuration](configuration.md)
- [CLI Usage](../../usage/cli/phone.md)
