# Bidirectional Key Sharing

## Overview

The phone and laptop are symmetric key-sharing peers. Either device can use keys stored on the other over the same Noise XX encrypted channel. The laptop sends `local.*` requests to operate on phone keys, and the phone sends `remote.*` requests to operate on laptop xkmsd backends.

## Architecture

```
Laptop                                Phone
+-------------------------------+     +-------------------------------+
|  xkey binary                  |     |  Android App                  |
|                               |     |                               |
|  +-------------------------+  |     |  +-------------------------+  |
|  | xkmsd bridge        |  |     |  | Android Keystore        |  |
|  | (Go SDK client)         |  |     |  | (TEE / StrongBox)       |  |
|  +------------+------------+  |     |  +------------+------------+  |
|               |               |     |               |               |
|  +------------v------------+  |     |  +------------v------------+  |
|  | JSON-RPC dispatcher     |  |     |  | JSON-RPC dispatcher     |  |
|  | local.* --> send         |  |     |  | remote.* --> send       |  |
|  | remote.* --> xkmsd  |  |     |  | local.* --> Keystore    |  |
|  +------------+------------+  |     |  +------------+------------+  |
|               |               |     |               |               |
|  +------------v------------+  |     |  +------------v------------+  |
|  | Noise XX Session        |<------>|  | Noise XX Session        |  |
|  +-------------------------+  |     |  +-------------------------+  |
+-------------------------------+     +-------------------------------+
               |                                     |
               +------ BLE GATT / USB (ADB) ---------+
```

Both sides run a JSON-RPC dispatcher that routes incoming requests to the appropriate handler and sends outgoing requests over the shared channel.

## xkmsd Bridge

The xkey binary bridges the phone to xkmsd backends on the laptop. When the phone sends a `remote.*` request, the bridge dispatches it to xkmsd via the Go SDK.

```go
type XkmsdBridge struct {
    client  transport.Client  // xkmsd Go SDK client
    session *NoiseSession     // Noise channel to phone
    logger  *slog.Logger
}

func (b *XkmsdBridge) HandleRemoteSign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
    // Dispatch to xkmsd backend
    sig, err := b.client.Sign(ctx, req.KeyID, req.Algorithm, req.Data,
        xkms.WithBackend(req.Backend))
    if err != nil {
        return nil, err
    }
    return &SignResponse{Signature: sig}, nil
}
```

The bridge connects to xkmsd using any supported transport:

| Transport | Connection |
|-----------|------------|
| Unix socket | `/var/run/xkmsd/xkmsd.sock` |
| gRPC | `grpc://localhost:8443` |
| REST | `https://localhost:8443` |
| QUIC | `quic://localhost:8443` |
| Embedded | In-process (no network) |

Configuration:

```yaml
xkmsd:
  transport: unix
  socket: /var/run/xkmsd/xkmsd.sock
  # Or for gRPC:
  # transport: grpc
  # url: https://localhost:8443
  # ca: /etc/xkmsd/ca.pem
  # cert: /etc/xkmsd/client.pem
  # key: /etc/xkmsd/client-key.pem
```

---

## Sharing Policies

### Phone to Laptop (Controlled by Phone)

The phone controls which of its keys the laptop can access. Policy is configured in the Android app settings.

| Policy | Behavior |
|--------|----------|
| `PRIVATE` | Only keys explicitly created for remote use are accessible |
| `SHARED` | All phone keys are accessible to the laptop |
| `ASK` | User is prompted on the phone for each laptop access request |

Default: `ASK`

When `ASK` is active, the phone displays a prompt:

```
Key Access Request

"laptop-hostname" wants to use key "sig-key" for signing.

[Allow Once]  [Allow Always]  [Deny]
```

### Laptop to Phone (Controlled by xkey Config)

The xkey binary controls which xkmsd backends the phone can access.

```yaml
xkmsd:
  sharing:
    policy: "shared"           # shared, restricted, or deny
    allowed_backends:          # whitelist (only when policy=restricted)
      - "tpm2"
      - "software"
    denied_backends:           # blacklist (applied in all policies)
      - "vault"
    allowed_operations:        # restrict operation types
      - "sign"
      - "verify"
      - "getPublicKey"
    denied_operations: []      # blacklist specific operations
```

| Policy | Behavior |
|--------|----------|
| `shared` | All backends accessible (minus denied_backends) |
| `restricted` | Only allowed_backends accessible |
| `deny` | No remote access (phone cannot use laptop keys) |

Default: `restricted` with `allowed_backends: ["tpm2", "software"]`

### Policy Enforcement

```
Phone sends remote.sign
  |
  v
Check sharing policy
  |
  +-- policy=deny --> return -32022 BackendDenied
  |
  +-- Check denied_backends
  |     +-- backend in list --> return -32022 BackendDenied
  |
  +-- policy=restricted
  |     +-- Check allowed_backends
  |           +-- backend NOT in list --> return -32022 BackendDenied
  |
  +-- Check denied_operations
  |     +-- operation in list --> return -32022 BackendDenied
  |
  +-- Check allowed_operations (if set)
  |     +-- operation NOT in list --> return -32022 BackendDenied
  |
  v
Dispatch to xkmsd
```

---

## Use Cases

### 1. Phone Signs with Laptop's TPM2 Key

A mobile application on the phone needs a signature from a TPM2-backed key on the laptop.

```
Phone App --> remote.sign(keyId:"tpm-key", backend:"tpm2") --> Laptop
Laptop --> xkmsd SDK --> TPM2 backend --> TPM2_Sign
Laptop --> result: {signature:"..."} --> Phone App
```

### 2. Laptop Signs with Phone's StrongBox Key

The desktop browser needs a WebAuthn assertion signed by a hardware key on the phone.

```
Browser --> xkey --> local.sign(keyId:"webauthn-key") --> Phone
Phone --> Biometric prompt --> User authenticates
Phone --> StrongBox sign --> result: {signature:"..."} --> Laptop
Laptop --> xkey --> Browser assertion
```

### 3. Shared FIDO2 Credentials Between Devices

FIDO2 credentials created on the phone can be discovered and used from the laptop for WebAuthn authentication.

```
Laptop --> local.listFido2Credentials(rpId:"example.com") --> Phone
Phone --> result: [{credentialId:"...", rpId:"example.com", ...}]
Laptop --> local.signFido2Assertion(credentialId:"...", ...) --> Phone
Phone --> Biometric --> StrongBox sign --> result --> Laptop
```

### 4. Phone Uses Laptop's SSH Keys

A terminal app on the phone needs SSH authentication using keys stored on the laptop.

```
Phone SSH App --> remote.sign(keyId:"ssh-ed25519", backend:"software") --> Laptop
Laptop --> xkmsd SDK --> Software backend --> Ed25519 sign
Laptop --> result: {signature:"..."} --> Phone SSH App
```

### 5. Laptop Generates Keys on Phone for Hardware Protection

The laptop creates keys on the phone to benefit from StrongBox hardware protection.

```
Laptop --> local.generateKey(keyId:"hw-sig", algorithm:"ES256",
           strongBox:true, requireBiometric:true) --> Phone
Phone --> StrongBox key generation
Phone --> result: {publicKey:"...", securityLevel:"strongbox"} --> Laptop
```

---

## FIDO2 Credential Sharing

FIDO2 credential sharing enables both devices to act as a unified authenticator.

### Credential Discovery

The laptop's FIDO2 authenticator can discover credentials stored on the phone using `local.listFido2Credentials`. This enables the laptop to offer phone-resident credentials during WebAuthn authentication without requiring the user to manually select the phone backend.

### Sign Counter Consistency

Sign counters must be monotonically increasing across both devices. The protocol handles this by:

1. The phone is the authoritative counter source for phone-resident credentials
2. `local.signFido2Assertion` atomically increments and returns the updated counter
3. The laptop never caches or independently increments phone credential counters

### Sharing Policy for FIDO2

FIDO2 credential sharing follows the phone's general sharing policy:

| Phone Policy | FIDO2 Behavior |
|-------------|----------------|
| `PRIVATE` | Only credentials explicitly marked "shareable" are visible |
| `SHARED` | All discoverable credentials are visible to the laptop |
| `ASK` | User prompted on phone when laptop discovers or signs with a credential |

### Credential Lifecycle

```
1. User registers on phone (CredentialProvider)
   Phone creates key in StrongBox
   Credential stored locally on phone

2. Laptop discovers shared credentials
   local.listFido2Credentials(rpId:"example.com")
   Phone returns matching credentials per sharing policy

3. Laptop authenticates with shared credential
   local.signFido2Assertion(credentialId:"...", clientDataHash:"...")
   Phone prompts biometric, signs, returns assertion + updated counter

4. User deletes credential on phone
   Credential removed from phone
   Next discovery from laptop will not include it
```

---

## Security Considerations

### Channel Security

All bidirectional traffic uses the same Noise XX encrypted channel. The Noise session provides:

- Mutual authentication via static Curve25519 keys
- Forward secrecy via ephemeral key exchange
- Authenticated encryption (ChaCha20-Poly1305)
- Protection against replay, reordering, and truncation

### Policy Isolation

Sharing policies are enforced independently on each side:

- Phone policies are enforced on the phone (cannot be bypassed by laptop)
- Laptop policies are enforced on the laptop (cannot be bypassed by phone)
- Neither side can escalate the other's policy

### Audit Logging

Both sides log cross-device operations for audit:

```yaml
# Laptop side
logging:
  remote_operations: true   # Log all remote.* requests from phone
  local_operations: true    # Log all local.* requests to phone
  include_key_ids: true     # Include key IDs in logs
  include_backends: true    # Include backend names in logs
```

---

## See Also

- [Protocol Specification](protocol.md) - Full method reference for local.* and remote.*
- [Attestation](attestation.md) - Verifying hardware backing
- [Transport](transport.md) - BLE and USB transport details
- [xkey Architecture](../architecture.md) - Overall xkey design
