# Initialization Guide

After installing go-xkms, these steps bring the system to a fully operational state. The process covers barrier initialization for at-rest encryption, PIN setup for access control, backend configuration, and verifying the system is ready.

## Prerequisites

- go-xkms binary installed (`xkmsctl` CLI available on `$PATH`)
- Configuration file at default location (`$HOME/.xkms.yaml`) or specified via `--config`
- For hardware backends: TPM 2.0 device (`/dev/tpmrm0`) or PKCS#11 token available

## Step 1: Configuration File

Create a configuration file with at minimum the server, backend, seal, and PIN sections. A minimal `xkmsd.yaml`:

```yaml
server:
  address: "0.0.0.0:8443"
  tls:
    cert_file: "/etc/xkms/server.pem"
    key_file: "/etc/xkms/server-key.pem"
    ca_file: "/etc/xkms/ca.pem"

backends:
  - id: software
    type: software
    data_dir: "/var/lib/xkms/keys"

seal:
  strategy: auto
  root_key_path: "sys/barrier/root-key"

pin:
  strategy: auto
  min_length: 6
  lockout:
    max_attempts: 5
    duration: 5m
    backoff: true
```

The `auto` strategy for both `seal` and `pin` selects the best available hardware option, falling back to software. For production, prefer an explicit `tpm2` or `pkcs11` strategy.

## Step 2: Initialize the Barrier

The barrier provides transparent at-rest encryption for all key material. It belongs to go-qrdb, and `xkmsctl` has no `barrier` verb: the server initializes and unseals it from the `seal` section above when `xkmsd` starts. See [Barrier Architecture](../seal/architecture.md).

On a desktop, `xkey barrier init` initializes the barrier. Run it before `xkey tpm` or `xkey pin` on a fresh data directory, because the go-qrdb file engine refuses a non-empty directory that lacks its format marker.

## Step 3: Set the Security Officer PIN

The SO PIN is the master PIN used for administrative operations. It must be set before the user PIN.

```bash
xkmsctl pin set-so
```

You will be prompted interactively:

```
Enter new SO PIN: ********
Confirm SO PIN: ********
SO PIN set successfully.
```

Requirements: minimum length from config (default 6 characters). Store this PIN securely -- it is needed for lockout recovery and user PIN management.

## Step 4: Set the User PIN

The user PIN controls day-to-day access. Requires the SO PIN for authorization.

```bash
xkmsctl pin set-user
```

```
Enter SO PIN: ********
Enter new User PIN: ********
Confirm User PIN: ********
User PIN set successfully.
```

## Step 5: Verify PIN Setup

Confirm both PINs are working and the lockout counter is clean:

```bash
# Verify user PIN
xkmsctl pin verify
# Enter User PIN: ********
# PIN verified successfully.

# Verify SO PIN
xkmsctl pin verify --type so
# Enter SO PIN: ********
# PIN verified successfully.

# Check lockout status
xkmsctl pin status
```

Expected status output:

```
PIN Status
  Strategy:        software
  SO PIN Set:      true
  User PIN Set:    true
  Failed Attempts: 0/5
  Locked:          false
```

## Step 6: Test Key Operations

Generate a test key to verify the system is fully operational:

```bash
# Generate a signing key
xkmsctl key generate test-key --key-type signing --algorithm ed25519

# List keys
xkmsctl key list

# Sign data
xkmsctl key sign test-key "hello world"

# Delete the test key when satisfied
xkmsctl key delete test-key
```

If all commands succeed, the barrier, PIN, and backend layers are operational.

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

See [Authentication Configuration](../configuration/auth.md) for the full reference, including composite authentication (mTLS + JWT), PKCS#11 token-backed client certificates, and RBAC role mapping.

## Daily Operations

The server unseals the barrier on each restart through the configured seal strategy. TPM 2.0 and PKCS#11 strategies unseal automatically because the hardware provides authentication. There is no `xkmsctl barrier` verb.

## Troubleshooting

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `pin: locked out due to too many failed attempts` | Exceeded max failed PIN attempts | Check `xkmsctl pin status` for recovery time, or reset immediately with `xkmsctl pin reset-lockout` (requires SO PIN) |
| `seal: barrier is sealed` | Key operation attempted while barrier is sealed | Restart `xkmsd` so the seal strategy unseals it |
| `seal: invalid credentials` | Wrong passphrase during unseal | Re-enter the correct passphrase |
| `backend not found` | Requested backend not defined in configuration | Verify the `backends` section in your configuration file |
| `pin: SO PIN authorization required` | Attempted user PIN set without SO PIN | Set the SO PIN first (Step 3) |

## See Also

- [PIN Commands](cli/pin.md) -- Full PIN CLI reference
- [Barrier Architecture](../seal/architecture.md) -- Encryption design and threat model
- [Configuration Reference](../configuration/README.md) -- Complete configuration options
- [Authentication Configuration](../configuration/auth.md) -- mTLS, JWT, OIDC, and RBAC
- [Getting Started (Backend Selection)](getting-started.md) -- Backend comparison and Go API examples
- [Bootstrap Commands](cli/bootstrap.md) -- Secure CA bundle bootstrap for new nodes
