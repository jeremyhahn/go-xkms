# Certificate Management CLI

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl cert`, the go-xkms server CLI (`cmd/xkmsctl/cert.go`): the server's certificate store, plus local CA and certificate generation.

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl cert`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> `xkey` has its own `xkey cert` command group with a different surface —
> see [the xkey CLI reference](README.md).

The `cert` command group does two different jobs:

- **Store commands** (`save`, `get`, `delete`, `list`, `exists`, `save-chain`,
  `get-chain`) read and write certificates in the certificate store of the
  server named by `--server`, keyed by key ID within the backend named by
  `--backend` (default `software`). There is no offline mode.
- **Generation commands** (`generate-ca`, `issue`) run entirely inside
  `xkmsctl`. They generate keys and certificates locally and print them or
  write them to files; nothing is sent to a server.

```
xkmsctl cert
├── save <key-id> <cert-file>
├── save-chain <key-id> <cert-file>...
├── get <key-id>
├── get-chain <key-id>
├── list
├── exists <key-id>
├── delete <key-id>
├── generate-ca              # Local self-signed CA
└── issue                    # Local certificate signed by a CA key file
```

## Store Commands

The store commands take the global `-o/--output` (`text`, `json` or `table`).

### save and save-chain

`save` reads a PEM certificate, checks that it parses as X.509, and stores it
under the key ID (`cmd/xkmsctl/cert.go:47`). `save-chain` stores several
certificates as one chain, ordered from leaf to root
(`cmd/xkmsctl/cert.go:322`).

```bash
xkmsctl cert save my-server-key server.crt
xkmsctl cert save-chain my-server-key server.crt intermediate.crt root.crt
```

### get and get-chain

Print the stored certificate or chain for a key ID.

```bash
xkmsctl cert get my-server-key
xkmsctl cert get-chain my-server-key -o json
```

### list, exists, delete

```bash
xkmsctl cert list
xkmsctl cert exists my-server-key
xkmsctl cert delete my-server-key
xkmsctl --backend pkcs11 cert list
```

## Generation Commands

Both commands print the certificate details, the certificate PEM and, unless
`--key-output` is given, the private key PEM to stdout. `--output` writes the
certificate to a file with mode 0644; `--key-output` writes the PKCS#8 private
key to a file with mode 0600 (`cmd/xkmsctl/cert.go:788`). Their local
`--output` hides the global `-o/--output` format flag.

### generate-ca

Generates a self-signed CA certificate and key (`cmd/xkmsctl/cert.go:713`;
flags at `cmd/xkmsctl/cert.go:1114`).

| Flag | Default | Description |
|------|---------|-------------|
| `--cn` | | Common name (required) |
| `--org` | `Go xKMS` | Organization |
| `--ou`, `--country`, `--province`, `--locality` | | Other subject fields |
| `--validity` | `3650` | Validity in days |
| `--key-algorithm` | `ecdsa` | `rsa`, `ecdsa` or `ed25519` |
| `--key-size` | `256` | RSA: 2048 or 4096; ECDSA: 256, 384 or 521 |
| `--output` | | Certificate file (PEM) |
| `--key-output` | | Private key file (PEM) |

```bash
xkmsctl cert generate-ca --cn "Example Root CA" --org "Example Corp" \
  --output ca.crt --key-output ca.key
```

### issue

Issues a server or client certificate signed by a CA certificate and key read
from files. The CA key may be PKCS#8, PKCS#1 (RSA) or SEC 1 (EC) PEM
(`cmd/xkmsctl/cert.go:938`; flags at `cmd/xkmsctl/cert.go:1128`).

| Flag | Default | Description |
|------|---------|-------------|
| `--ca-cert` | | CA certificate file, PEM (required) |
| `--ca-key` | | CA private key file, PEM (required) |
| `--cn` | | Common name (required) |
| `--type` | `server` | `server` or `client` |
| `--org`, `--ou`, `--country`, `--province`, `--locality` | | Subject fields |
| `--validity` | `365` | Validity in days |
| `--key-algorithm` | `ecdsa` | `rsa`, `ecdsa` or `ed25519` |
| `--key-size` | `256` | RSA: 2048 or 4096; ECDSA: 256, 384 or 521 |
| `--dns` | | DNS SANs, comma-separated |
| `--ip` | | IP SANs, comma-separated |
| `--email` | | Email SANs, comma-separated |
| `--output` | | Certificate file (PEM) |
| `--key-output` | | Private key file (PEM) |

```bash
# A TLS server certificate
xkmsctl cert issue --ca-cert ca.crt --ca-key ca.key --cn server.example.com \
  --dns "server.example.com,www.example.com" --ip 192.0.2.10 \
  --output server.crt --key-output server.key

# An mTLS client certificate
xkmsctl cert issue --ca-cert ca.crt --ca-key ca.key --cn client@example.com \
  --type client --output client.crt --key-output client.key
```

## Example: local PKI, then store the result

```bash
xkmsctl cert generate-ca --cn "Example Root CA" --output ca.crt --key-output ca.key
xkmsctl cert issue --ca-cert ca.crt --ca-key ca.key --cn server.example.com \
  --dns server.example.com --output server.crt --key-output server.key
xkmsctl cert save-chain server-key server.crt ca.crt
```

For certificates signed by the server's own CA instead of a local key file,
use [`xkmsctl ca issue` and `xkmsctl ca sign-csr`](./ca.md).

## See Also

- [Certificate Authority CLI](./ca.md)
- [Certificate Management Guide](../certificate-management.md)
- [Key Management CLI](./key.md)
