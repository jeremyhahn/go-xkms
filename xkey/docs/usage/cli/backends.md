# Backends CLI Command

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: `xkmsctl backends`, the go-xkms server CLI (`cmd/xkmsctl/backends.go`).

> **Scope:** this page documents the go-xkms **server** CLI `xkmsctl backends`
> (source: `cmd/xkmsctl/`), **not** the `xkey` desktop CLI. It lives under
> `xkey/docs/` for historical reasons.
> There is no `xkey` equivalent. For the xkey command tree see
> [the xkey CLI reference](README.md).

The `backends` command lists the cryptographic backends an xkmsd server has
and shows a summary of each one's capabilities. Both subcommands connect to the
server named by the global `--server` flag and ask it
(`cmd/xkmsctl/backends.go:43`); there is no offline mode, so the answer
reflects the **server's** build and configuration, not the `xkmsctl` binary's.

## Available Commands

### backends list

```bash
xkmsctl backends list
```

**Output (text or table format):**
```
Available Backends:
  - software
  - pkcs11
  - tpm2
```

**Output (JSON format):**
```bash
xkmsctl --output json backends list
```

```json
{
  "backends": ["software", "pkcs11", "tpm2"]
}
```

The entries are the backend IDs the server reports.

### backends info

```bash
xkmsctl backends info <backend-name>
```

**Output (text or table format)** (`cmd/xkmsctl/output.go:124`):
```
Backend: software
Capabilities:
  Keys:            true
  Hardware Backed: false
  Signing:         true
  Decryption:      true
  Key Rotation:    true
```

**Output (JSON format):**
```bash
xkmsctl --output json backends info software
```

```json
{
  "backend": "software",
  "capabilities": {
    "keys": true,
    "hardware_backed": false,
    "signing": true,
    "decryption": true,
    "key_rotation": true
  }
}
```

`Hardware Backed` is true when either the backend's capabilities or its backend
info say so (`cmd/xkmsctl/backends.go:122`).

## Backend Types

The backend IDs `xkmsctl --backend` accepts are `software`, `pkcs11`, `tpm2`,
`awskms`, `gcpkms`, `azurekv` and `vault`. Which of them a given server offers
depends on its build tags and configuration. The full per-backend capability
matrix is normative in
[crypto backends — engineering](../../../../docs/crypto-backends/engineering.md#backend-capability-matrix).

## Connecting to a server

```bash
# Default: the local unix socket (xkms-data/xkms.sock)
xkmsctl backends list

# A remote server over REST, verifying it against a private CA
xkmsctl --server https://kms.example.com:8443 --tls-ca /path/to/ca.pem backends list
```

## Global Flags

The root flags most relevant here (`xkmsctl --help`):

```
-s, --server <url>      xkms server URL (default: xkms-data/xkms.sock); unix://, http(s)://, grpc(s)://, quic://
    --transport <name>  Client transport: rest, grpc, quic, mcp, unix, embedded (default "unix")
-o, --output <format>   Output format: text, json, table (default "text")
    --tls-ca <path>     CA certificate for server verification
    --config <path>     Config file (default is $HOME/.xkms.yaml)
-v, --verbose           Verbose output
```

## Build Tags

A backend exists in a server only if the server binary was built with its tag.
Every optional backend toggle defaults on in the Makefile; see
[Build toggles](../../../../docs/crypto-backends/engineering.md#build-toggles).

```bash
# Drop backends the deployment does not use
make build WITH_VAULT=0 WITH_AZURE=0

# Or build with no optional backend at all
make build-minimal
```

`WITH_AZURE` is a provider umbrella: it sets `WITH_AZURE_KV` together with the
Azure object-storage toggles (root `Makefile:55`).

## Troubleshooting

### Backend Not Listed

The server was built without it, or its configuration does not enable it.
Rebuild with the toggle back on (for example `make build WITH_VAULT=1`). A
configuration that names a backend the binary was built without fails with
`xkms: backend "<name>" is not compiled into this binary; build with
WITH_<FEATURE>=1 (build tag "<tag>")` (`pkg/xkms/errors_auto.go:47`).

### Server Connection Failed

```bash
# Verbose output shows the connection step
xkmsctl --verbose --server https://kms.example.com:8443 --tls-ca /path/to/ca.pem backends list
```

## See Also

- [Getting Started Guide](../getting-started.md) - Backend selection and configuration
- [Crypto backends](../../../../docs/crypto-backends/user.md)
- [TPM2 Backend](../../../../docs/tpm2/user.md)
- [PKCS#11 Backend](../../../../docs/pkcs11-backend/user.md)
