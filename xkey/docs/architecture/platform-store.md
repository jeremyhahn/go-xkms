# xkey Platform Store

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `xkey platform-store` CLI over xkmsd's named-secret store; the [seal](../seal/) feature folder is normative for sealing.

The Platform Store provides a named-secret API for storing and retrieving sealed credentials on the local machine. Secrets are encrypted at rest by the storage backend the store is built on, typically a sealed backend using the configured sealing strategy (TPM2, PKCS#11, cloud KMS, or passphrase).

## Overview

The Platform Store operates through the xkmsd service. The xkey CLI and GUI both delegate to xkmsd over the SDK transport, which manages the actual sealing backend. This architecture means any backend supported by xkmsd (TPM2, PKCS#11, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, passphrase) is available for secret protection.

```
xkey CLI / GUI
      |
      | SDK transport (Unix socket, gRPC, REST, QUIC)
      v
   xkmsd
      |
      v
 PlatformStore  -->  SealedPlatformStore  -->  storage.Backend (sealed)
```

`SealedPlatformStore` (`pkg/seal/platform_store.go:92`) is built by
`NewPlatformStore(backend storage.Backend, logger)` (`platform_store.go:100`);
the backend supplies the encryption.

## CLI Commands

All commands require a running xkmsd server.

### Server selection

The endpoint is resolved once, in `xkey/cmd/xkey/cmd/xkmsd_client.go:179-182`, and shared by
every command group that talks to xkmsd (`platform-store`, `ca`):

1. `--xkmsd-url`
2. `XKMSD_URL`, then `XKEY_XKMSD_URL`
3. the `xkmsd_url` config key
4. `xkmsd.address` in the xkey config

The URL scheme selects the SDK transport (`xkmsd_client.go:140-147`):

| Scheme | Transport |
|--------|-----------|
| `unix://` | Unix domain socket |
| `http://`, `https://` | REST |
| `grpc://`, `grpcs://` | gRPC |
| `quic://` | HTTP/3 |
| `mcp://`, `mcps://` | JSON-RPC |

`XKMSD_TOKEN` supplies a bearer token. `--tls-ca`, `XKMSD_TLS_CA`, or
`xkmsd.tls_ca_file` supplies the CA bundle used to verify the TLS-bearing
transports (`https`, `grpcs`, `quic`, `mcps`); without one the system trust
store is used.

### `xkey platform-store put <name>`

Store a secret in the platform store.

```bash
# Store a secret by value
echo -n "s3cret" | xkey platform-store put my-secret --value-stdin

# Store a secret from a file
xkey platform-store put my-cert --file /path/to/cert.pem
```

| Flag | Description |
|------|-------------|
| `--value-stdin` | Read the secret value from standard input |
| `--file` | Path to file containing the secret |

There is no `--value` value flag: a value on the command line is visible to
every other process on the host via `ps`. The value comes from
`--value-stdin` or the `XKEY_PLATFORM_STORE_VALUE` environment variable.
`--value-stdin`/`XKEY_PLATFORM_STORE_VALUE` and `--file` are mutually
exclusive. One must be provided.

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

The commands are defined in `xkey/cmd/xkey/cmd/seal_store.go:102-289`. There
is no GUI binding for the platform store.

## Well-Known Secret Names

The following secret names are reserved for platform automation.

| Name | Description |
|------|-------------|
| `platform/user-pin` | User PIN for FIDO2 authenticator and password store unlock |
| `platform/luks-passphrase` | Passphrase for LUKS2 encrypted container unlock |
| `platform/pkcs11-pin` | PIN for PKCS#11 hardware token access |
| `platform/tpm2-auth` | TPM 2.0 authorization value |
| `platform/vault-token` | HashiCorp Vault token |

These names are defined as constants in `pkg/seal/platform_store.go:31-44`:

```go
const (
    SecretUserPIN        = "platform/user-pin"
    SecretLUKSPassphrase = "platform/luks-passphrase"
    SecretPKCS11PIN      = "platform/pkcs11-pin"
    SecretTPM2Auth       = "platform/tpm2-auth"
    SecretVaultToken     = "platform/vault-token"
)
```

## Sealing Strategy Selection

There is no implicit preference order. `PlatformSealer.BestStrategy()`
(`pkg/seal/platform_sealer.go:157`) returns `ErrNoStrategySpecified` unless the
config sets an explicit `PreferenceOrder`. Strategy IDs are `tpm2`, `pkcs11`,
`awskms`, `gcpkms`, `azurekv` and `vault` (`pkg/seal/strategy.go:109-124`),
plus `none`, `passphrase` and `shamir` re-exported from go-qrdb.

## Related Packages

- `pkg/seal/platform_store.go` -- SealedPlatformStore implementation
- `pkg/seal/platform_sealer.go` -- Multi-strategy PlatformSealer
- `pkg/seal/strategy.go` -- SealingStrategy interface and strategy IDs
- `xkey/cmd/xkey/cmd/seal_store.go` -- CLI commands

## See Also

- [Seal](../seal/) -- Barrier, sealing strategies and auto-unseal
- [Password](../password/) -- Static password management
- [LUKS](../luks/) -- Encrypted container management
