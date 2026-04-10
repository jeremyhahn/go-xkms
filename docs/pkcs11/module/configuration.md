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

## Configuration Precedence

Configuration loads in the following order (highest precedence first):

1. Environment variables
2. Configuration file
3. Default values

## Unix Socket Configuration

For local connections using Unix domain sockets:

```bash
# Start the xkms daemon
xkms daemon --unix /var/run/xkms/xkms.sock

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

```bash
# Start the xkms server
xkms server --listen :9443

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

```bash
# Start the xkms server with TLS
xkms server --listen :9443 \
  --tls-cert /etc/xkms/server.crt \
  --tls-key /etc/xkms/server.key \
  --tls-ca /etc/xkms/ca.crt

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
target = xkms.prod.internal:9443
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
