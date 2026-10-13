# Initialization Guide

> **Status: REFERENCE** · Last verified: 2026-10-13
> First-run walkthrough for xkmsd and xkmsctl; superseded by [xkmsd-configuration](../../../docs/xkmsd-configuration/user.md), [pin-management](../../../docs/pin-management/user.md) and [seal/](../seal/architecture.md). Where they disagree, the feature folders win.

After installing go-xkms, these steps bring the system to a fully operational state. The process covers barrier initialization for at-rest encryption, PIN setup for access control, backend configuration, and verifying the system is ready.

## Prerequisites

- go-xkms binary installed (`xkmsctl` CLI available on `$PATH`)
- `xkmsctl` configuration at the default location (`$HOME/.xkms.yaml`, `cmd/xkmsctl/root.go:116`) or specified via `--config`
- For hardware backends: TPM 2.0 device (`/dev/tpmrm0`) or PKCS#11 token available

## Step 1: Configuration File

Create an `xkmsd.yaml` with at least the server, backend, barrier and PIN sections (`Config`, `pkg/config/config.go:35`). A minimal example:

```yaml
server:
  host: ""            # all interfaces
  rest_port: 8443

tls:
  enabled: true
  cert_file: "/etc/xkms/server.pem"
  key_file: "/etc/xkms/server-key.pem"
  ca_file: "/etc/xkms/ca.pem"

backends:
  software:
    enabled: true
    path: "/var/lib/xkms/keys"

barrier:
  enabled: true
  strategy: tpm2
  root_key_path: "sys/barrier/root-key"

pin:
  enabled: true
  strategy: software
  max_attempts: 5
  lockout_duration: 5m
```

`barrier.strategy` takes `none`, `passphrase`, `shamir`, `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv` or `vault`; empty means `passphrase` (`BarrierConfig`, `pkg/config/config.go:160`). `pin` has only `enabled`, `strategy`, `max_attempts` and `lockout_duration` (`PINConfig`, `config.go:261`); `pin.strategy` is `auto` (the default), `software` or `tpm2` (`pkg/server/pin_manager.go:32-37`). The full key reference is [xkmsd-configuration/engineering.md](../../../docs/xkmsd-configuration/engineering.md).

## Step 2: Initialize the Barrier

The barrier provides transparent at-rest encryption for all key material. It belongs to go-qrdb, and `xkmsctl` has no `barrier` verb: the server initializes and unseals it from the `barrier` section above when `xkmsd` starts. See [Barrier Architecture](../seal/architecture.md).

On a desktop, `xkey barrier init` initializes the barrier. Run it before `xkey tpm` or `xkey pin` on a fresh data directory, because the go-qrdb file engine refuses a non-empty directory that lacks its format marker.

## Step 3: Set the Security Officer PIN

The SO PIN is the master PIN used for administrative operations. It must be set before the user PIN.

```bash
xkmsctl pin so-set
```

The new PIN is prompted for when `--new-pin` is omitted; `--new-pin -` reads it from stdin. Replacing an existing SO PIN needs `--current-pin` (`cmd/xkmsctl/pin.go:500-501`). Store this PIN securely -- it is needed for lockout recovery and user PIN management.

## Step 4: Set the User PIN

The user PIN controls day-to-day access. It requires the SO PIN for authorization.

```bash
xkmsctl pin user-set
```

`--so-pin` and `--new-pin` are prompted for when omitted (`pin.go:511-512`).

## Step 5: Verify PIN Setup

```bash
# Verify the user PIN
xkmsctl pin user-verify

# Verify the SO PIN
xkmsctl pin so-verify

# Check lockout state
xkmsctl pin lockout
```

Both verify verbs take `--pin` (prompted when omitted, `pin.go:508`, `:519`).

## Step 6: Test Key Operations

Generate a test key to verify the system is fully operational:

```bash
# Generate a signing key
xkmsctl key generate test-key --key-type signing --key-algorithm ed25519

# List keys
xkmsctl key list

# Sign data
xkmsctl key sign test-key "hello world"

# Delete the test key when satisfied
xkmsctl key delete test-key
```

`key generate`, `list`, `delete` and `sign <key-id> <data>` are defined in `cmd/xkmsctl/key.go:42`, `:160`, `:265` and `:314`. If all commands succeed, the barrier, PIN, and backend layers are operational.

## Step 7: (Optional) Set Up PIV

If using a PIV-capable backend (PKCS#11 with a SmartCard-HSM or YubiKey):

```bash
# List available PIV slots
xkmsctl piv list --backend pkcs11

# Generate an authentication key in slot 9a
xkmsctl piv generate 9a --backend pkcs11 --algorithm ecdsap256 --subject "CN=Authentication"

# Generate a CSR for external CA signing
xkmsctl piv csr 9a --backend pkcs11 --subject "CN=Authentication,O=MyOrg"
```

## Step 8: (Optional) Configure mTLS

For production deployments with mutual TLS authentication, add client certificate verification to the server configuration:

```yaml
tls:
  enabled: true
  cert_file: /etc/xkms/tls/server.pem
  key_file: /etc/xkms/tls/server-key.pem
  ca_file: /etc/xkms/tls/ca.pem
  client_auth: require_and_verify
  client_cas:
    - /etc/xkms/tls/ca.pem

auth:
  enabled: true
  type: mtls
  mtls: true
  enable_rbac: true
```

See [Authentication Configuration](../../../docs/xkmsd-configuration/engineering.md#authentication-and-client-certificate-settings) for the full reference, including composite authentication (mTLS + JWT), PKCS#11 token-backed client certificates, and RBAC role mapping.

## Daily Operations

The server unseals the barrier on each restart through the configured seal strategy. TPM 2.0 and PKCS#11 strategies unseal automatically because the hardware provides authentication; `passphrase` and `shamir` never auto-unseal and wait for the operator (`config.go:166-172`). There is no `xkmsctl barrier` verb.

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| PIN locked out after too many failed attempts | Check `xkmsctl pin lockout`, or reset it with `xkmsctl pin lockout-reset` (requires the SO PIN, `pin.go:522`) |
| Key operation fails because the barrier is sealed | Restart `xkmsd` so the seal strategy unseals it, or complete the passphrase/Shamir unseal |
| `backend not found` | Verify the `backends` section in your configuration file |
| User PIN cannot be set | Set the SO PIN first (Step 3) |

## See Also

- [PIN Commands](cli/pin.md) -- Full PIN CLI reference
- [Barrier Architecture](../seal/architecture.md) -- Encryption design and threat model
- [Configuration Reference](../configuration/README.md) -- Complete configuration options
- [Authentication Configuration](../../../docs/xkmsd-configuration/engineering.md#authentication-and-client-certificate-settings) -- mTLS, JWT, and composite authentication
- [Getting Started (Backend Selection)](getting-started.md) -- Backend comparison and Go API examples
- [Bootstrap Commands](cli/bootstrap.md) -- Secure CA bundle bootstrap for new nodes
