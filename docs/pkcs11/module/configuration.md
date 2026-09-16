# Configuration

The PKCS#11 module supports configuration via environment variables and configuration files.

## Environment Variables

Environment variables take precedence over configuration file settings.

| Variable | Description | Default |
|----------|-------------|---------|
| `XKMS_PKCS11_TARGET` | Server connection target | `unix:///var/run/xkms/xkms.sock` |
| `XKMS_PKCS11_TLS_ENABLED` | Enable TLS | `false` |
| `XKMS_PKCS11_TLS_CERT` | Client certificate file | - |
| `XKMS_PKCS11_TLS_KEY` | Client private key file | - |
| `XKMS_PKCS11_TLS_CA` | CA certificate file | - |
| `XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` | Opt out of the mandatory-TLS guard for non-`unix://` targets (test/dev only) | `false` |
| `XKMS_PKCS11_TIMEOUT` | Operation timeout | `30s` |

## Configuration File

Default location: `/etc/xkms/pkcs11.conf`

### File Format

INI-style format with key = value pairs:

```ini
# PKCS#11 Module Configuration

# Server target address
# Formats:
#   unix:///path/to/socket  - Unix domain socket
#   dns:///host:port        - DNS-based TCP
#   host:port               - Direct TCP
target = unix:///var/run/xkms/xkms.sock

# TLS configuration
tls_enabled = false
tls_cert = /etc/xkms/client.crt
tls_key = /etc/xkms/client.key
tls_ca = /etc/xkms/ca.crt

# Operation timeout (Go duration format)
timeout = 30s
```

### Configuration File Permissions

The configuration file must not be group- or world-readable. `LoadFromFile` stats the file before parsing it and
refuses to load one whose mode has any of the `0077` bits set (`ErrConfigFilePermissions`), because the INI
format accepts `so_pin` and `user_pin` in cleartext:

```bash
chmod 600 /etc/xkms/pkcs11.conf
```

## Configuration Precedence

Configuration loads in the following order (highest precedence first):

1. Environment variables
2. Configuration file
3. Default values

## Unix Socket Configuration

For local connections using Unix domain sockets:

The socket path is a YAML setting, not a flag (`pkg/config/config.go:219-230`).

```yaml
# /etc/xkms/xkmsd.yaml
protocols:
  unix: true

unix:
  enabled: true
  socket_path: "/var/run/xkms/xkms.sock"
  socket_mode: "0660"
  protocol: "grpc"
```

```bash
# Start the xkms daemon
xkmsd -config /etc/xkms/xkmsd.yaml

# Configure PKCS#11 module
export XKMS_PKCS11_TARGET=unix:///var/run/xkms/xkms.sock
```

Configuration file:

```ini
target = unix:///var/run/xkms/xkms.sock
timeout = 30s
```

Unix socket advantages:
- Fastest connection method
- Kernel-enforced access control
- No network overhead

## TCP Configuration

For remote connections over TCP:

The daemon binary is `xkmsd` and it takes no listen flag -- the gRPC port comes
from `server.grpc_port` in the YAML config (`cmd/xkmsd/main.go:67-74`,
`pkg/config/config.go:202`). 9443 is what every shipped `configs/*.yaml` sets.

```yaml
# /etc/xkms/xkmsd.yaml
server:
  host: "0.0.0.0"
  grpc_port: 9443

protocols:
  grpc: true
```

```bash
# Start the xkms daemon
xkmsd -config /etc/xkms/xkmsd.yaml

# Configure PKCS#11 module
export XKMS_PKCS11_TARGET=xkms.example.com:9443
```

Configuration file:

```ini
target = xkms.example.com:9443
timeout = 30s
```

## TLS Configuration

For secure remote connections:

TLS is configured in the `tls:` section of the daemon YAML, not by flags
(`pkg/config/config.go:240-253`). `xkmsd` refuses to start without TLS enabled.

```yaml
# /etc/xkms/xkmsd.yaml
tls:
  enabled: true
  cert_file: /etc/xkms/server.crt
  key_file: /etc/xkms/server.key
  ca_file: /etc/xkms/ca.crt
```

```bash
# Start the xkms daemon with TLS
xkmsd -config /etc/xkms/xkmsd.yaml

# Configure PKCS#11 module
export XKMS_PKCS11_TARGET=xkms.example.com:9443
export XKMS_PKCS11_TLS_ENABLED=true
export XKMS_PKCS11_TLS_CA=/etc/xkms/ca.crt
```

Configuration file:

```ini
target = xkms.example.com:9443
tls_enabled = true
tls_ca = /etc/xkms/ca.crt
timeout = 30s
```

## Transport Security

TLS is mandatory for any target other than `unix://` -- a `unix://` socket never leaves the host, but PKCS#11
traffic to a remote target can carry raw exported key material, and the gRPC transport falls back to plaintext
credentials whenever TLS is disabled. `Validate` refuses a remote target with `tls_enabled = false`
(`ErrInsecureRemoteTarget`) unless the operator explicitly sets `allow_insecure_transport`:

```ini
target = kms-dev.example.com:9443
tls_enabled = false
allow_insecure_transport = true
```

`allow_insecure_transport` (or `XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT=true`) exists only for test and development
use against a loopback or containerized server. It must never be set in a production configuration.

A configuration that fails to load or fails validation now fails `C_Initialize` closed -- the module does not
fall back to default values when the configuration file is unreadable, malformed, or invalid.

## mTLS Configuration

For mutual TLS authentication (client certificates):

```bash
# Environment variables
export XKMS_PKCS11_TARGET=xkms.example.com:9443
export XKMS_PKCS11_TLS_ENABLED=true
export XKMS_PKCS11_TLS_CERT=/etc/xkms/client.crt
export XKMS_PKCS11_TLS_KEY=/etc/xkms/client.key
export XKMS_PKCS11_TLS_CA=/etc/xkms/ca.crt
```

Configuration file:

```ini
target = xkms.example.com:9443
tls_enabled = true
tls_cert = /etc/xkms/client.crt
tls_key = /etc/xkms/client.key
tls_ca = /etc/xkms/ca.crt
timeout = 30s
```

## Timeout Configuration

The timeout applies to individual operations. Use Go duration format:

```ini
# Examples
timeout = 5s      # 5 seconds
timeout = 100ms   # 100 milliseconds
timeout = 1m      # 1 minute
timeout = 30s     # 30 seconds (default)
```

For high-latency networks, increase the timeout:

```ini
target = remote-xkms.example.com:9443
timeout = 60s
```

## DNS-Based Configuration

For DNS-based service discovery:

```ini
target = dns:///xkms.service.consul:9443
```

This uses DNS SRV records for service discovery and load balancing.

## Configuration Validation

The module validates configuration at load time:

- Target format must be valid (unix://, dns://, or host:port)
- TLS certificate and key files must exist if specified
- TLS CA file must exist if specified
- Timeout must be non-negative

Validation errors:

| Error | Cause |
|-------|-------|
| `target is required` | Empty target |
| `invalid target format` | Unrecognized target format |
| `TLS certificate file is required` | TLS key without cert |
| `TLS key file is required` | TLS cert without key |
| `TLS certificate file not found` | Cert file does not exist |
| `timeout must be non-negative` | Negative timeout value |

## Example Configurations

### Development (Local)

```ini
target = unix:///tmp/xkms.sock
timeout = 5s
```

### Production (Remote with mTLS)

```ini
target = kms-prod.example.com:9443
tls_enabled = true
tls_cert = /etc/xkms/client.crt
tls_key = /etc/xkms/client.key
tls_ca = /etc/xkms/ca.crt
timeout = 30s
```

### High-Availability (DNS)

```ini
target = dns:///xkms.service.consul:9443
tls_enabled = true
tls_ca = /etc/xkms/ca.crt
timeout = 60s
```

## Storage Modes

The module persists its token and object state (labels, PIN hashes, failed-attempt
counters, object metadata) in one of three modes, selected by
`XKMS_PKCS11_STORAGE_TYPE` (config key `storage_type`; see
`pkg/pkcs11/module/config.go`):

| Mode | Value | State lives in | Network |
|------|-------|----------------|---------|
| Memory | `memory` | process memory (non-durable) | none |
| File | `file` | local disk at `XKMS_PKCS11_STORAGE_PATH` | none |
| Remote | `remote` | xkmsd, over the active transport | required |

### Local modes (`memory` / `file`) — offline, SoftHSM-style

The module runs with no network dependency. With `file`, an optional **offline seal**
(`XKMS_PKCS11_MODE=local`, `pkg/pkcs11/localseal`) encrypts the on-disk key directory
under the User PIN via the qrdb barrier (AES-256-GCM at rest); the User PIN unseals it
at `C_Login` and the store re-seals at `C_Logout`/`C_Finalize`. `XKMS_PKCS11_SEAL_STRATEGY`
selects the strategy (`passphrase` default; `none` for the cleartext dev path).

### Remote mode (`remote`) — server-authoritative, cluster-shareable

The module keeps **no** local state; every token/object record is stored in xkmsd via
the `PKCS11State*` RPCs (`pkg/pkcs11/module/storage_remote.go`; server store
`pkg/pkcs11state`). `XKMS_PKCS11_TOKEN_LABEL` names the token and the `tenant_id` config key
scopes it (empty is the system scope). When xkmsd embeds a clustered qrdb node the store is Raft-replicated, so
several module instances can share one server-side token.

**Lockout is server-authoritative here.** The consecutive-failed-PIN counters (which
drive `CKF_USER_PIN_LOCKED`) live in dedicated keys and are incremented atomically via
`PKCS11StateCAS` (a linearizable compare-and-swap over the replicated store), so
concurrent failed logins across clients accumulate against one budget rather than losing
updates — a PIN cannot be brute-forced past its budget by racing multiple modules. The
SessionManager's in-memory counters are an optimistic cache reconciled to the durable
value. See `docs/pkcs11/ROADMAP.md` (X1) and `pkg/pkcs11/module/storage.go`.

## Token Auto-Initialization

For testing, the module can initialize its token automatically on load instead of requiring a separate
`C_InitToken` call:

```ini
auto_init_token = true
so_pin = 12345678
user_pin = 123456
token_label = test-token
```

Equivalent environment variables: `XKMS_PKCS11_AUTO_INIT_TOKEN`, `XKMS_PKCS11_SO_PIN`, `XKMS_PKCS11_USER_PIN`,
`XKMS_PKCS11_TOKEN_LABEL`. Whichever path sets the PINs, they are never stored in the clear -- the token stores a
salted Argon2id verifier for each, and re-initializing an already-initialized token (`C_InitToken`) requires the
existing SO PIN. See [Security: PIN Storage and Lockout](security.md#pin-storage-and-lockout) for the hashing and
lockout details. Because the config file can carry `so_pin`/`user_pin` in cleartext INI, the file permission
requirement above applies with extra force when `auto_init_token` is used.

## Programmatic Configuration

When using the module as a Go library:

```go
// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
    "time"

    "github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func main() {
    cfg := &module.Config{
        Target:  "unix:///var/run/xkms/xkms.sock",
        Timeout: 30 * time.Second,
        TLS: module.TLSConfig{
            Enabled: false,
        },
    }

    cfg.SetDefaults()
    if err := cfg.Validate(); err != nil {
        panic(err)
    }

    m, _ := module.New(module.WithConfig(cfg))
    rv := m.Initialize(cfg)
    if rv != module.CKR_OK {
        panic("initialization failed")
    }
    defer m.Finalize()
}
```
