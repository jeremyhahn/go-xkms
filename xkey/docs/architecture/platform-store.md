# xkey Platform Store

The Platform Store provides a named-secret API for storing and retrieving sealed credentials on the local machine. Secrets are transparently encrypted at rest using the best available sealing mechanism (TPM2, PKCS#11, cloud KMS, or software-based).

## Overview

The Platform Store operates through the xkmsd service. The xkey CLI and GUI both delegate to xkmsd over the SDK transport, which manages the actual sealing backend. This architecture means any backend supported by xkmsd (TPM2, PKCS#11, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, software) is available for secret protection.

```
xkey CLI / GUI
      |
      | SDK transport (Unix socket, gRPC, REST, QUIC)
      v
   xkmsd
      |
      v
 PlatformStore  -->  SealedPlatformStore  -->  storage.Backend
      |
      v
 PlatformSealer  -->  Best available sealer (TPM2 > PKCS#11 > Cloud > Software)
```

## CLI Commands

All commands require a running xkmsd server. Specify the server URL with `--xkmsd-url` or `XKEY_XKMSD_URL`.

### `xkey platform-store put <name>`

Store a secret in the platform store.

```bash
# Store a secret by value
xkey platform-store put my-secret --value "s3cret"

# Store a secret from a file
xkey platform-store put my-cert --file /path/to/cert.pem
```

| Flag | Description |
|------|-------------|
| `--value` | Secret value to store |
| `--file` | Path to file containing the secret |

`--value` and `--file` are mutually exclusive. One must be provided.

### `xkey platform-store get <name>`

Retrieve a secret from the platform store.

```bash
# Retrieve to stdout
xkey platform-store get my-secret

# Save to file
xkey platform-store get my-cert --output /tmp/cert.pem

# Pipe to clipboard
xkey platform-store get my-secret | xclip -selection clipboard
```

| Flag | Description |
|------|-------------|
| `--output` | Write secret to file instead of stdout |

### `xkey platform-store delete <name>`

Delete a secret from the platform store. Aliases: `rm`

```bash
xkey platform-store delete my-secret
```

### `xkey platform-store list`

List the names of all secrets in the platform store. Aliases: `ls`

```bash
xkey platform-store list
```

Only secret names are displayed; values are not shown.

### `xkey platform-store reseal [name]`

Re-encrypt a secret with the current sealing key. Useful after key rotation, TPM ownership changes, or PCR policy updates.

```bash
# Reseal a specific secret
xkey platform-store reseal my-secret

# Reseal all secrets
xkey platform-store reseal --all
```

| Flag | Description |
|------|-------------|
| `--all` | Reseal all secrets at once |

### `xkey platform-store status`

Show the current state of the platform store.

```bash
xkey platform-store status
```

Output includes:
- **Available** -- Whether the store is accessible
- **Sealer** -- Active sealing strategy ID
- **Secret Count** -- Number of stored secrets
- **Secrets** -- Names of all stored secrets

## GUI Service Methods

The `PlatformStoreServiceGUI` is bound to the Wails runtime, making every exported method callable from the Svelte frontend.

| Method | Signature | Description |
|--------|-----------|-------------|
| `Put` | `Put(name, secret string) error` | Store a secret |
| `Get` | `Get(name string) (string, error)` | Retrieve a secret |
| `Delete` | `Delete(name string) error` | Delete a secret |
| `List` | `List() ([]string, error)` | List all secret names |
| `Reseal` | `Reseal(name string) error` | Reseal a specific secret |
| `ResealAll` | `ResealAll() error` | Reseal all secrets |
| `GetStatus` | `GetStatus() (*PlatformStoreStatus, error)` | Get store status |

All GUI methods delegate to the SDK transport client connected to xkmsd.

## Well-Known Secret Names

The following secret names are reserved for platform automation. The auto-unseal system and xkey services use these to retrieve credentials during boot.

| Name | Description |
|------|-------------|
| `platform/user-pin` | User PIN for FIDO2 authenticator and password store unlock |
| `platform/luks-passphrase` | Passphrase for LUKS2 encrypted container unlock |
| `platform/pkcs11-pin` | PIN for PKCS#11 hardware token access |
| `platform/tpm2-auth` | TPM 2.0 authorization value |

These names are defined as constants in `pkg/seal/platform_store.go`:

```go
const (
    SecretUserPIN        = "platform/user-pin"
    SecretLUKSPassphrase = "platform/luks-passphrase"
    SecretPKCS11PIN      = "platform/pkcs11-pin"
    SecretTPM2Auth       = "platform/tpm2-auth"
)
```

## Sealing Strategy Selection

The PlatformSealer selects the best available strategy in preference order:

1. **TPM2** -- Hardware-backed, PCR-bound sealing
2. **PKCS#11** -- HSM token-based sealing
3. **AWS KMS** -- Cloud KMS sealing
4. **GCP KMS** -- Cloud KMS sealing
5. **Azure Key Vault** -- Cloud KMS sealing
6. **HashiCorp Vault** -- Cloud/on-prem KMS sealing
7. **Software** -- Argon2id password-based (always available as fallback)

Each sealed blob is tagged with its strategy ID in metadata, so unseal automatically routes to the correct backend regardless of the current preference order.

## Boot Automation Sequence

During system boot, the platform store enables unattended secret retrieval:

```
1. xkmsd starts (systemd/openrc)
2. Barrier unseal (auto or manual password)
3. PlatformStore becomes available
4. Services retrieve sealed credentials:
   - LUKS passphrase --> unseal encrypted container
   - PKCS#11 PIN --> unlock HSM token
   - User PIN --> unlock password store
   - TPM2 auth --> authenticate TPM operations
5. xkey daemon starts with credentials ready
```

See [Auto-Unseal](auto-unseal.md) for the full automated flow.

## Related Packages

- `pkg/seal/platform_store.go` -- SealedPlatformStore implementation
- `pkg/seal/platform_sealer.go` -- Multi-strategy PlatformSealer
- `pkg/seal/strategy.go` -- SealingStrategy interface and strategy IDs
- `pkg/seal/barrier.go` -- Barrier (transparent AES-256-GCM storage encryption)
- `xkey/pkg/gui/services/platform_store_service.go` -- GUI service bindings

## See Also

- [Auto-Unseal](auto-unseal.md) -- How auto-unseal works
- [Password Guide](password.md) -- Static password management
- [LUKS Guide](luks.md) -- Encrypted container management
