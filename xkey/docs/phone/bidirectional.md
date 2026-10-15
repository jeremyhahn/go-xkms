# Bidirectional Key Sharing

> **Status: REFERENCE** · Last verified: 2026-10-13
> Background for phone ↔ laptop key sharing; superseded by [phone/architecture.md](architecture.md) and [phone-hsm/architecture.md](../phone-hsm/architecture.md). Where they disagree, the feature folders win. Phone-side (Android app) behaviour is unverified here.

## Overview

The phone and laptop are symmetric key-sharing peers. Either device can use keys stored on the other over the same Noise XX encrypted channel. The laptop sends `local.*` requests to operate on phone keys, and the phone sends `remote.*` requests to operate on laptop xkmsd backends.

## Architecture

```
Laptop                                Phone
+-------------------------------+     +-------------------------------+
|  xkey binary                  |     |  Android App                  |
|                               |     |                               |
|  +-------------------------+  |     |  +-------------------------+  |
|  | xkmsd bridge            |  |     |  | Android Keystore        |  |
|  | (Go SDK client)         |  |     |  | (TEE / StrongBox)       |  |
|  +------------+------------+  |     |  +------------+------------+  |
|               |               |     |               |               |
|  +------------v------------+  |     |  +------------v------------+  |
|  | JSON-RPC dispatcher     |  |     |  | JSON-RPC dispatcher     |  |
|  | local.* --> send        |  |     |  | remote.* --> send       |  |
|  | remote.* --> xkmsd      |  |     |  | local.* --> Keystore    |  |
|  +------------+------------+  |     |  +------------+------------+  |
|               |               |     |               |               |
|  +------------v------------+  |     |  +------------v------------+  |
|  | Noise XX Session        |<------>|  | Noise XX Session        |  |
|  +-------------------------+  |     |  +-------------------------+  |
+-------------------------------+     +-------------------------------+
               |                                     |
               +---- BLE GATT / USB (AOA) / TCP -----+
```

Both sides run a JSON-RPC dispatcher that routes incoming requests to the appropriate handler and sends outgoing requests over the shared channel. The transports are described in [transport.md](transport.md).

## xkmsd Bridge

The xkey binary bridges the phone to xkmsd backends on the laptop. When the phone sends a `remote.*` request, `pairing.Bridge` (`xkey/pkg/pairing/bridge.go:151`) dispatches it to xkmsd through the Go SDK transport client.

The bridge reaches xkmsd over the unix socket only; any other `xkmsd.protocol`
fails with `ErrXKMSdUnsupportedProtocol` (`createXKMSdClient`,
`xkey/cmd/xkey/cmd/dial_xkmsd.go`). The socket is the qrdb node's TLS
listener, so the bridge dials it over TLS and presents the configured client
certificate. The keys are read by `loadXKMSdBridgeConfig` in the same file:

```yaml
xkmsd:
  enabled: true
  protocol: unix                  # default; the only supported value
  address: "<path to xkms.sock>"  # default xkms-data/xkms.sock
  tls_ca_file: ""                 # CA for the socket's certificate; empty = system trust store
  tls_cert_file: ""               # client certificate that admits xkey
  tls_key_file: ""
  connect_timeout: 10s
  request_timeout: 30s
  sharing:
    allowed_backends: []          # empty = all backends
    denied_backends: []
  tpm:
    enrollment: false
    device: ""
    pcr_bank: ""
```

The phone-bridge wiring itself is built only with the
`ble` build tag (`xkey/cmd/xkey/cmd/fido2_phone_bridge.go`).

---

## Sharing Policies

### Phone to Laptop (Controlled by Phone)

The phone decides which of its keys the laptop may use. On the wire, a key's
`shareable` flag is reported in `KeyInfo` and changed with
`local.setKeyPolicy` (`xkey/pkg/pairing/protocol_local.go:223`); refusals
come back as `-32018` `ErrorCodeShareDenied` or `-32019`
`ErrorCodeShareNotExportable` (`xkey/pkg/pairing/protocol.go:47`). How the
Android app presents and prompts for these policies is phone-side and not
verified here.

### Laptop to Phone (Controlled by xkey Config)

The xkey binary controls which xkmsd backends the phone can access, with
`xkmsd.sharing.allowed_backends` and `xkmsd.sharing.denied_backends` (copied
into `BridgeConfig`, `bridge.go:39`). There is no policy mode and no
per-operation allow or deny list.

### Policy Enforcement

`Bridge.isBackendAllowed` (`bridge.go:343`):

```
Phone sends remote.* naming a backend
  |
  +-- backend in denied_backends      --> -32008 BackendDenied
  |
  +-- allowed_backends non-empty and
  |   backend not in it               --> -32008 BackendDenied
  |
  v
Dispatch to xkmsd
```

The deny list always wins; an empty allow list admits every backend not denied.

---

## Use Cases

### 1. Phone Signs with Laptop's TPM2 Key

```
Phone App --> remote.sign(backend:"tpm2", keyId:"tpm-key") --> Laptop
Laptop bridge --> xkmsd SDK --> TPM2 backend --> TPM2_Sign
Laptop --> result: {signature:"..."} --> Phone App
```

### 2. Laptop Signs with Phone's StrongBox Key

```
xkey --> local.sign(keyId:"webauthn-key") --> Phone
Phone --> Biometric prompt (if the key requires it) --> User authenticates
Phone --> StrongBox sign --> result: {signature:"..."} --> Laptop
```

### 3. Shared FIDO2 Credentials Between Devices

```
Laptop --> local.listFido2Credentials(rpId:"example.com") --> Phone
Phone --> result: [{credentialId:"...", rpId:"example.com", ...}]
Laptop --> local.signFido2Assertion(credentialId:"...", ...) --> Phone
Phone --> Biometric --> StrongBox sign --> result --> Laptop
```

### 4. Laptop Generates Keys on Phone for Hardware Protection

```
Laptop --> local.generateKey(keyId:"hw-sig", algorithm:"ES256",
           strongBoxBacked:true, biometricRequired:true) --> Phone
Phone --> StrongBox key generation
Phone --> result: {publicKeyDer:"...", securityLevel:"strongbox"} --> Laptop
```

---

## FIDO2 Credential Sharing

### Credential Discovery

The laptop discovers credentials stored on the phone with `local.listFido2Credentials` (`protocol_local.go:43`), so phone-resident credentials can be offered during WebAuthn authentication.

### Sign Counter Consistency

The phone is the authoritative counter source for phone-resident credentials:
`local.signFido2Assertion` returns the updated `signCount`
(`LocalSignFido2AssertionResult`, `protocol_local.go:376`), and the laptop does
not increment phone credential counters itself.

### Credential Lifecycle

```
1. User registers on phone (CredentialProvider)
   Phone creates key in StrongBox

2. Laptop discovers credentials
   local.listFido2Credentials(rpId:"example.com")

3. Laptop authenticates with a credential
   local.signFido2Assertion(credentialId:"...", clientDataHash:"...")
   Phone prompts biometric, signs, returns assertion + updated counter

4. User deletes credential on phone
   Next discovery from laptop will not include it
```

---

## Security Considerations

### Channel Security

All bidirectional traffic uses the same Noise channel,
`Noise_XX_25519_ChaChaPoly_SHA256` (`xkey/pkg/pairing/noise.go:30`):

- Mutual authentication via static Curve25519 keys
- Forward secrecy via ephemeral key exchange
- Authenticated encryption (ChaCha20-Poly1305)
- Protection against replay, reordering, and truncation

### Policy Isolation

Sharing policies are enforced independently on each side:

- Phone policies are enforced on the phone (cannot be bypassed by laptop)
- Laptop policies are enforced on the laptop (cannot be bypassed by phone)

### Audit Logging

The bridge writes security audit events to `BridgeConfig.AuditLogger`,
tagged with the device ID and name; when it is nil no audit events are
written. There is no config key for it.

---

## See Also

- [Protocol Specification](protocol.md) - Full method reference for local.* and remote.*
- [Attestation](attestation.md) - Verifying hardware backing
- [Transport](transport.md) - BLE and USB transport details
