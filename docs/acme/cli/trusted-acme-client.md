# trusted-acme-client

Multi-account ACME client CLI for certificate lifecycle management and TPM device enrollment.

## Overview

`trusted-acme-client` is a command-line tool that manages certificates across multiple ACME accounts and Certificate Authorities simultaneously. It supports:

- Multiple ACME accounts with independent CA configurations
- Named certificate specifications with per-cert account binding
- Cross-signing certificates between CAs
- Automatic renewal via a background daemon
- TPM device enrollment and attestation (device-attest-01)
- Pluggable key storage via go-xkms (software, TPM2, PKCS#11, cloud KMS)
- Pluggable certificate/account storage via go-objstore

## Installation

```bash
# Build from source
make build-client

# Install to ~/.local/bin/
make install

# Or build optimized binary
make dist-client
```

## Configuration

The client reads configuration from YAML, environment variables, and command-line flags (in increasing precedence order).

Default location: `/etc/trusted-acme/client-config.yaml`

Override with `--config /path/to/config.yaml` or `ACME_CLIENT_CONFIG`.

### Configuration Structure

```yaml
# Optional tenant identifier for multi-tenant deployments
tenant_id: ""

storage:
  backend: "filesystem"        # go-objstore backend
  options:
    path: "/var/lib/trusted-acme/client"

xkms:
  backend: "software"          # Key store backend
  options: {}

logging:
  level: "info"                # debug, info, warn, error
  format: "json"               # json, text
  output: "stdout"             # stdout, stderr, or file path

challenge:
  http01:
    port: "80"
    web_root: ""
    use_proxy: false
  dns01:
    provider: ""
    credentials: {}
    ttl: 300

# ACME accounts keyed by name
accounts:
  my-ca:
    directory: "https://acme.example.com/acme/directory"
    email: "admin@example.com"
    key:
      algorithm: "ecdsa"       # ecdsa, rsa, ed25519
      size: 256                # ECDSA: 256, 384; RSA: 2048, 4096
      store: "software"        # Key store for account key
    transport:
      tls_ca: "/etc/ssl/certs/ca.pem"
      insecure: false
      timeout: 60s
    eab:
      kid: ""
      hmac_key: ""

# Certificate specifications keyed by name
certificates:
  web-server:
    account: "my-ca"           # References an account above
    subject:
      common_name: "www.example.com"
      organization: "Example Corp"
    sans:
      - "www.example.com"
      - "example.com"
    key:
      algorithm: "ecdsa"
      size: 256
      store: "software"
    challenge: "http-01"       # http-01, dns-01, device-attest-01
    deploy:
      cert_path: "/etc/ssl/certs/web.pem"
      key_path: "/etc/ssl/private/web-key.pem"
      chain_path: "/etc/ssl/certs/web-chain.pem"
      post_hook: "systemctl reload nginx"
    renewal:
      enabled: true
      threshold: 0.33          # Renew at 33% remaining validity
      max_retries: 5
      retry_interval: "1h"
    cross_signer:
      account: ""              # Account name for cross-signing CA
      profile: ""              # Certificate profile on cross-signing CA
```

See [examples/multi-account.yaml](../examples/multi-account.yaml) for a complete multi-account configuration.

## Command Reference

```
trusted-acme-client [global flags] <command> <subcommand> [flags]
```

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `/etc/trusted-acme/client-config.yaml` | Path to configuration file |
| `--log-level` | `info` | Log level: debug, info, warn, error |
| `--log-format` | `json` | Log format: json, text |

### account

Manage ACME accounts.

#### account add \<name\>

Register a new ACME account with the CA specified in the named account config.

```bash
trusted-acme-client account add my-ca
```

If the account is not yet defined in the config, use flags to provide details:

| Flag | Description |
|------|-------------|
| `--directory` | ACME directory URL |
| `--email` | Contact email |
| `--eab-kid` | External Account Binding key ID |
| `--eab-hmac` | External Account Binding HMAC key |

#### account list

List all configured accounts and their registration status.

```bash
trusted-acme-client account list
```

#### account show \<name\>

Show details for a specific account including registration status, key info, and associated certificates.

```bash
trusted-acme-client account show my-ca
```

#### account remove \<name\>

Deactivate and remove an ACME account.

```bash
trusted-acme-client account remove my-ca
```

### cert

Manage certificates.

#### cert request \<name\>

Request a certificate using the named certificate specification from the config.

```bash
trusted-acme-client cert request web-server
```

#### cert list

List all certificate specifications and their current status (pending, valid, expired, revoked).

```bash
trusted-acme-client cert list
```

#### cert show \<name\>

Show certificate details including expiry, SANs, issuer, and renewal schedule.

```bash
trusted-acme-client cert show web-server
```

#### cert renew \<name\>

Renew a certificate immediately, bypassing the renewal threshold check.

```bash
trusted-acme-client cert renew web-server
```

#### cert revoke \<name\>

Revoke a certificate.

```bash
trusted-acme-client cert revoke web-server --reason 0
```

| Flag | Default | Description |
|------|---------|-------------|
| `--reason` | `0` | Revocation reason code (0=unspecified, 1=key compromise, 3=affiliation changed, 4=superseded, 5=cessation) |

#### cert deploy \<name\>

Deploy the certificate and key to the filesystem paths defined in the certificate's `deploy` section and execute the post-hook.

```bash
trusted-acme-client cert deploy web-server
```

### device

TPM device enrollment and attestation.

#### device enroll

Enroll a TPM device using the enroll-01 challenge (TCG Section 6.2). Uses the certificate spec with `challenge: device-attest-01`.

```bash
trusted-acme-client device enroll --cert-name host-identity
```

| Flag | Description |
|------|-------------|
| `--cert-name` | Certificate spec name to use for enrollment |
| `--device-id` | Device identifier (defaults to hostname) |

#### device attest

Perform TPM attestation using device-attest-01.

```bash
trusted-acme-client device attest --cert-name host-identity --pcrs 0,1,2,3,4,5,6,7
```

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-name` | | Certificate spec name |
| `--pcrs` | `0,1,2,3,4,5,6,7` | Comma-separated PCR indices |

### service

Auto-renewal daemon.

#### service start

Start the auto-renewal daemon. Monitors all certificates with `renewal.enabled: true` and renews them when they approach expiration.

```bash
trusted-acme-client service start
```

The daemon runs the renewal check loop, executes deploy hooks on successful renewal, and respects retry configuration per certificate.

#### service status

Show the renewal service status including next check time and certificate states.

```bash
trusted-acme-client service status
```

### version

Print version, build info, and supported features.

```bash
trusted-acme-client version
```

## Key Store Types

The `key.store` field in account and certificate configs selects the go-xkms backend for key storage and operations.

| Store | Description |
|-------|-------------|
| `software` | Software-based PKCS#8 keys on the local filesystem |
| `tpm2` | TPM 2.0 hardware module |
| `pkcs11` | PKCS#11 token (HSM, smart card) |
| `awskms` | AWS Key Management Service |
| `gcpkms` | Google Cloud KMS |
| `azurekv` | Azure Key Vault |
| `vault` | HashiCorp Vault Transit |

Configure backend-specific options in the top-level `xkms.options` section or per-key via `key.store_options`.

## Challenge Types

| Challenge | Description |
|-----------|-------------|
| `http-01` | HTTP validation via `/.well-known/acme-challenge/` token |
| `dns-01` | DNS TXT record validation at `_acme-challenge.<domain>` |
| `device-attest-01` | TPM-based device attestation (requires TPM key store) |

## Environment Variables

All configuration fields can be set via environment variables using the `ACME_CLIENT_` prefix with underscores replacing dots and hyphens.

| Variable | Description |
|----------|-------------|
| `ACME_CLIENT_CONFIG` | Path to configuration file |
| `ACME_CLIENT_TENANT_ID` | Tenant identifier |
| `ACME_CLIENT_LOG_LEVEL` | Log level |
| `ACME_CLIENT_LOG_FORMAT` | Log format |
| `ACME_CLIENT_STORAGE_BACKEND` | Storage backend name |
| `ACME_CLIENT_XKMS_BACKEND` | XKMS key store backend name |

## Examples

### Register accounts and request a certificate

```bash
# Register both accounts
trusted-acme-client account add trusted-ca
trusted-acme-client account add letsencrypt

# Request and deploy a certificate
trusted-acme-client cert request web-production
trusted-acme-client cert deploy web-production
```

### Start the auto-renewal daemon

```bash
trusted-acme-client --config /etc/trusted-acme/client-config.yaml service start
```

### TPM device enrollment

```bash
trusted-acme-client account add trusted-ca
trusted-acme-client device enroll --cert-name host-identity
```

### List all certificates and their status

```bash
trusted-acme-client cert list
```

### Cross-signed certificate workflow

```bash
# Register both CAs
trusted-acme-client account add trusted-ca
trusted-acme-client account add letsencrypt

# Request from Let's Encrypt, cross-sign with trusted-ca
trusted-acme-client cert request public-web
```

## See Also

- [Example multi-account config](../examples/multi-account.yaml)
- [ACME Documentation](../acme/README.md)
- [trusted-acme-server](trusted-acme-server.md)
- [cactl](cactl.md)
