# xkey auth -- Server Authentication

Manage authentication with xkms servers. Server entries and JWT tokens are stored in `~/.xkey/data/auth/`, encrypted by the local barrier when active.

## Command Tree

```
xkey auth
├── register   Register with a new xkms server
├── login      Authenticate to a registered server
├── status     Show authentication status for all servers
└── token      Print current JWT token for a server
```

## auth register

Register with a new xkms server. Establishes a connection, verifies the server identity, and stores the server entry in the local registry.

**Usage:**

```bash
xkey auth register --server <url> --email <login-key> [--spki-pin <pin>] [--setup-token <token>]
```

The registration ceremony runs against a local CTAP2 authenticator -- a real
security key, or `xkey fido2` running. It fails if no authenticator can be
opened; no credential is ever fabricated locally.

**Flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | Server URL (required) |
| `--spki-pin` | string | SPKI SHA-256 pin for certificate pinning |
| `--setup-token` | string | Pre-authorized enrollment token from server first boot |
| `--email` | string | Canonical email login key to enroll (required) |
| `--display-name` | string | Human-readable account name (default: the login key) |

The ceremony is addressed by the **email login key**: the server resolves the
account with `GetUserByEmail`, so `--email` is the only identifier that can
reach a principal. There is no default -- an OS account name is a different
identifier, and on a relying party with public registration enabled a lookup
that misses is a sign-up, enrolling the credential onto an account nobody
created. `--username` is the deprecated spelling of the same flag and still
carries the value.

**Examples:**

```bash
# Register with SPKI pin (trust-on-first-use)
xkey auth register --server https://kms.example.com:8443 --email alice@example.com \
    --spki-pin e5f6a7b8...

# Register with a setup token
xkey auth register --server https://kms.example.com:8443 --email alice@example.com \
    --setup-token eyJhbGciOi...
```

## auth login

Authenticate to a registered server using WebAuthn. On success, the resulting JWT token is stored for subsequent API calls.

**Usage:**

```bash
xkey auth login --server <url> --email <login-key>
```

**Flags:**

| Flag | Type | Description |
|------|------|-------------|
| `--server` | string | Server URL (required) |
| `--email` | string | Canonical email login key to authenticate (required) |

**Example:**

```bash
xkey auth login --server https://kms.example.com:8443 --email alice@example.com
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

  Server:         grpc://kms-dev.internal:9090
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

- [Bootstrap Architecture](../../bootstrap/README.md) -- Trust establishment overview
- [Share Management](./share.md) -- Shamir share operations
- [CLI Reference](./README.md) -- Full CLI command index
