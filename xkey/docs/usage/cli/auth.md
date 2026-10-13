# xkey auth -- Server Authentication

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the `xkey auth` command group (`xkey/cmd/xkey/cmd/auth.go`, `auth_session.go`).

Manage authentication with xkms servers. Server entries and tokens are stored
under `data/auth/` in the xkey home (`~/.xkey` by default, or `$XKEY_HOME`),
encrypted at rest when a barrier is active (`xkey/cmd/xkey/cmd/auth.go:323`).

## Command Tree

```
xkey auth
├── register   Register with a new xkms server
├── login      Authenticate to a registered server
├── logout     Revoke and remove a stored session
├── refresh    Rotate a PIV session's token pair
├── status     Show authentication status for all servers
└── token      Print current JWT token for a server
```

## auth register

Register with a new xkms server. Establishes a connection, verifies the server identity, and stores the server entry in the local registry.

**Usage:**

```bash
xkey auth register --server <url> --email <login-key> [--tls-ca <bundle>] [--spki-pin <pin>] [--setup-token <token>] [--pin-stdin]
```

The registration ceremony runs against a local CTAP2 authenticator -- a real
security key, or `xkey fido2` running. It fails if no authenticator can be
opened; no credential is ever fabricated locally.

**Flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | Server URL (required) |
| `--spki-pin` | string | SPKI SHA-256 pin for certificate pinning |
| `--tls-ca` | string | PEM CA bundle to verify the server against |
| `--setup-token` | string | Pre-authorized enrollment token from server first boot |
| `--email` | string | Canonical email login key to enroll (required) |
| `--display-name` | string | Human-readable account name (default: the login key) |
| `--pin-stdin` | bool | Read the authenticator's CTAP2 PIN from stdin |

The ceremony is addressed by the **email login key**: the server resolves the
account with `GetUserByEmail`, so `--email` is the only identifier that can
reach a principal. There is no default -- an OS account name is a different
identifier, and on a relying party with public registration enabled a lookup
that misses is a sign-up, enrolling the credential onto an account nobody
created.

An authenticator with a CTAP2 PIN set refuses the ceremony without the PIN.
Supply it with `--pin-stdin` or the `XKEY_PIN` environment variable, in that
order of precedence; there is no `--pin` value flag. This is the
authenticator's PIN and is unrelated to `--spki-pin`.

### Server trust

The server is verified against, in combination:

1. the system root certificates,
2. every CA in the xKey trust store -- anything added with `xkey trust add`
   whose purpose is `user-ca`, `bootstrap-ca`, or `general`,
3. the `--tls-ca` bundle, when given.

Each of those is an **addition** to verification, never a bypass. The
attestation purposes (`tpm-manufacturer`, `android-hardware`,
`idevid-issuer`) are deliberately not TLS anchors: they anchor device
attestation chains, and a session to a server is not one. `synced`
certificates, received from a paired device, anchor nothing.

`--spki-pin` is different in kind. It pins the server's public key directly
(trust-on-first-use) and is the route to a server whose CA is nowhere on this
host. The pin is recorded on the server entry, so it only has to be passed
once: later `auth register` and `auth login` runs against the same server
reuse it. Passing `--spki-pin` together with `--tls-ca` verifies both -- the
chain against the bundle *and* the pin against the leaf.

**Examples:**

```bash
# Register against a server whose CA is already in the trust store
xkey trust add ca-chain.crt --purpose user-ca --source "file:ca-chain.crt"
xkey auth register --server https://kms.example.com:8443 --email alice@example.com

# Register against a CA bundle that is not in the trust store
xkey auth register --server https://kms.example.com:8443 --email alice@example.com \
    --tls-ca ca-chain.crt

# Register with SPKI pin (trust-on-first-use)
xkey auth register --server https://kms.example.com:8443 --email alice@example.com \
    --spki-pin e5f6a7b8...

# Register with a setup token
xkey auth register --server https://kms.example.com:8443 --email alice@example.com \
    --setup-token eyJhbGciOi...
```

## auth login

Authenticate to a registered server using WebAuthn, or with `--piv` using a
PIV slot certificate over mTLS. On success the issued token is stored for
subsequent API calls. A PIV login also stores a refresh token; a WebAuthn
login does not.

**Usage:**

```bash
xkey auth login --server <url> --email <login-key> [--tls-ca <bundle>] [--pin-stdin]
xkey auth login --server <url> --piv [--slot 9a] [--backend software|pkcs11]
```

**Flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | Server URL (required) |
| `--email` | string | Canonical email login key to authenticate (required for WebAuthn) |
| `--tls-ca` | string | PEM CA bundle to verify the server against |
| `--pin-stdin` | bool | Read the authenticator's CTAP2 PIN from stdin (WebAuthn) |
| `--piv` | bool | Authenticate with a PIV slot certificate over mTLS |
| `--slot` | string | PIV slot (default `9a`, with `--piv`) |
| `--backend` | string | PIV key backend, `software` or `pkcs11` (default `software`, with `--piv`) |
| `--barrier-password-file`, `--barrier-password-stdin` | | Barrier password for the software PIV key store |

A `--backend software` PIV key exists only for the process that generated it;
use `--backend pkcs11` for a persistent hardware token.

Login verifies the server the same way `auth register` does, plus the SPKI pin
recorded on the server entry when there is one.

**Example:**

```bash
xkey auth login --server https://kms.example.com:8443 --email alice@example.com
xkey auth login --server https://kms.example.com:8443 --piv --slot 9c --backend pkcs11
```

## auth logout

Remove a stored session. When the session carries a refresh token (PIV login),
the refresh token is revoked on the server first, and the local entry is
deleted only once that succeeds. A WebAuthn session has nothing to revoke and
only its local entry is removed. The only flag is `--server` (required).

```bash
xkey auth logout --server https://kms.example.com:8443
```

## auth refresh

Rotate a stored session's access and refresh token pair. Only PIV sessions
carry a refresh token; for a WebAuthn session the command fails with
`ErrAuthRefreshTokenMissing`. The server detects reuse of a rotated refresh
token and revokes the whole token family, after which a fresh login is needed.
The only flag is `--server` (required).

```bash
xkey auth refresh --server https://kms.example.com:8443
```

## auth status

Show authentication status for all registered servers, including connection status and token validity.

**Usage:**

```bash
xkey auth status [--server <url>]
```

**Flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | Filter to a specific server URL (optional) |

**Example:**

```bash
xkey auth status
```

**Output:**

```
Registered Servers (2):

  Server:         https://kms.example.com:8443
  Protocol:       rest
  Registered:     2025-06-15T10:30:00Z
  Last Connected: 2025-06-15T14:22:00Z
  Token:          valid (webauthn, expires in 23h45m)

  Server:         grpc://kms-dev.example.com:9090
  Protocol:       grpc
  Registered:     2025-06-10T08:00:00Z
  Last Connected: never
  Token:          none
```

## auth token

Print the raw JWT token for a registered server to stdout. Suitable for piping to other commands or setting as an environment variable.

**Usage:**

```bash
xkey auth token --server <url>
```

**Flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | Server URL (required) |

**Examples:**

```bash
# Print token to stdout
xkey auth token --server https://kms.example.com:8443

# Set as environment variable
export XKMS_TOKEN=$(xkey auth token --server https://kms.example.com:8443)

# Use with xkmsctl
xkmsctl --server https://kms.example.com:8443 --token $(xkey auth token --server https://kms.example.com:8443) key list
```

Returns a non-zero exit code if no token exists or the token has expired.

## See Also

- [Bootstrap Architecture](../../../../docs/trust-bootstrap/architecture.md) -- Trust establishment overview
- [CLI Reference](./README.md) -- Full CLI command index
