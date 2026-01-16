# Configuration

The PKCS#11 module can be configured via YAML configuration file or environment variables.

## Configuration File

Default location: `/etc/gokeychain/pkcs11.yaml`

```yaml
pkcs11:
  # Backend mode: embedded | unix | rest | grpc | quic
  mode: embedded

  # Embedded backend configuration
  # Links directly against libkeychain.so
  embedded:
    library_path: /usr/lib/libkeychain.so
    config_path: /etc/gokeychain/config.yaml

  # Unix socket backend configuration
  # Direct IPC to keychain daemon using go-codec protocol
  unix:
    socket_path: /var/run/keychain/keychain.sock
    timeout_ms: 5000
    # Codec: cbor | msgpack | json (default: msgpack)
    codec: msgpack

  # REST backend configuration
  # HTTP/HTTPS API client
  rest:
    base_url: https://localhost:8443
    tls_ca_file: /etc/gokeychain/ca.crt
    tls_cert_file: /etc/gokeychain/client.crt
    tls_key_file: /etc/gokeychain/client.key
    timeout_ms: 10000
    # Skip TLS verification (not recommended for production)
    tls_insecure: false

  # gRPC backend configuration
  # Protocol Buffers RPC client
  grpc:
    address: localhost:9443
    tls_enabled: true
    tls_ca_file: /etc/gokeychain/ca.crt
    tls_cert_file: /etc/gokeychain/client.crt
    tls_key_file: /etc/gokeychain/client.key
    # Connection timeout
    timeout_ms: 10000
    # Keep-alive interval
    keepalive_ms: 30000

  # QUIC backend configuration
  # HTTP/3 over UDP client
  quic:
    address: localhost:8443
    tls_ca_file: /etc/gokeychain/ca.crt
    tls_cert_file: /etc/gokeychain/client.crt
    tls_key_file: /etc/gokeychain/client.key
    # 0-RTT early data (requires session resumption)
    enable_0rtt: true
    # Max idle timeout
    idle_timeout_ms: 30000

# Token definitions
# Each token appears as a separate slot in PKCS#11
tokens:
  - slot_id: 0
    label: "GO-KEYCHAIN"
    # Backend to use for this token (inherits from pkcs11.mode if not set)
    backend: default
    # PIN for user login (can also use KEYCHAIN_PIN env var)
    # pin: 123456
    # SO PIN for security officer login
    # so_pin: 87654321
    # Serial number (auto-generated if not set)
    # serial: "0001"
    # Token flags
    flags:
      # Token requires login for private key operations
      login_required: true
      # Token supports user PIN change
      user_pin_change: true
      # Token is write-protected
      write_protected: false

  # Example: Separate token for certificates
  - slot_id: 1
    label: "GO-KEYCHAIN-CERTS"
    backend: default
    flags:
      login_required: false
      write_protected: true
```

## Environment Variables

Environment variables override configuration file settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `KEYCHAIN_PKCS11_CONFIG` | Path to configuration file | `/etc/gokeychain/pkcs11.yaml` |
| `KEYCHAIN_PKCS11_MODE` | Backend mode | `embedded` |
| `KEYCHAIN_PKCS11_LIBRARY` | Path to libkeychain.so (embedded mode) | `/usr/lib/libkeychain.so` |
| `KEYCHAIN_PKCS11_SOCKET` | Unix socket path (unix mode) | `/var/run/keychain/keychain.sock` |
| `KEYCHAIN_PKCS11_URL` | REST base URL (rest mode) | `https://localhost:8443` |
| `KEYCHAIN_PKCS11_GRPC_ADDR` | gRPC address (grpc mode) | `localhost:9443` |
| `KEYCHAIN_PKCS11_QUIC_ADDR` | QUIC address (quic mode) | `localhost:8443` |
| `KEYCHAIN_PKCS11_TLS_CA` | TLS CA certificate file | - |
| `KEYCHAIN_PKCS11_TLS_CERT` | TLS client certificate file | - |
| `KEYCHAIN_PKCS11_TLS_KEY` | TLS client key file | - |
| `KEYCHAIN_PKCS11_TLS_INSECURE` | Skip TLS verification | `false` |
| `KEYCHAIN_PKCS11_TIMEOUT` | Operation timeout (ms) | `5000` |
| `KEYCHAIN_PIN` | Default user PIN | - |
| `KEYCHAIN_SO_PIN` | Default SO PIN | - |
| `KEYCHAIN_DEBUG` | Enable debug logging | `false` |
| `KEYCHAIN_LOG_FILE` | Log file path | stderr |

## Configuration by Mode

### Embedded Mode

Minimal configuration for single-process applications:

```bash
export KEYCHAIN_PKCS11_MODE=embedded
export KEYCHAIN_PKCS11_LIBRARY=/usr/lib/libkeychain.so
```

Or in YAML:

```yaml
pkcs11:
  mode: embedded
  embedded:
    library_path: /usr/lib/libkeychain.so
```

### Unix Mode

For multi-process deployments on the same host:

```bash
# Start the daemon
keychain daemon --unix /var/run/keychain/keychain.sock

# Configure PKCS#11 module
export KEYCHAIN_PKCS11_MODE=unix
export KEYCHAIN_PKCS11_SOCKET=/var/run/keychain/keychain.sock
```

Unix mode features:
- SO_PEERCRED for kernel-verified authentication
- go-codec serialization (CBOR/MsgPack/JSON)
- Multiplexed streams over single connection
- 1-5 microsecond latency

### REST Mode

For remote access with web integration:

```bash
# Start the REST server
keychain server --rest --listen :8443 \
  --tls-cert /etc/gokeychain/server.crt \
  --tls-key /etc/gokeychain/server.key

# Configure PKCS#11 module
export KEYCHAIN_PKCS11_MODE=rest
export KEYCHAIN_PKCS11_URL=https://keychain.example.com:8443
export KEYCHAIN_PKCS11_TLS_CA=/etc/gokeychain/ca.crt
```

### gRPC Mode

For high-performance remote access:

```bash
# Start the gRPC server
keychain server --grpc --listen :9443 \
  --tls-cert /etc/gokeychain/server.crt \
  --tls-key /etc/gokeychain/server.key

# Configure PKCS#11 module
export KEYCHAIN_PKCS11_MODE=grpc
export KEYCHAIN_PKCS11_GRPC_ADDR=keychain.example.com:9443
export KEYCHAIN_PKCS11_TLS_CA=/etc/gokeychain/ca.crt
```

### QUIC Mode

For low-latency remote access:

```bash
# Start the QUIC server
keychain server --quic --listen :8443 \
  --tls-cert /etc/gokeychain/server.crt \
  --tls-key /etc/gokeychain/server.key

# Configure PKCS#11 module
export KEYCHAIN_PKCS11_MODE=quic
export KEYCHAIN_PKCS11_QUIC_ADDR=keychain.example.com:8443
export KEYCHAIN_PKCS11_TLS_CA=/etc/gokeychain/ca.crt
```

## Token Configuration

### Multiple Tokens

Configure separate tokens for different purposes:

```yaml
tokens:
  # Primary signing token
  - slot_id: 0
    label: "SIGNING-KEYS"
    flags:
      login_required: true

  # Certificate storage (public access)
  - slot_id: 1
    label: "CERTIFICATES"
    flags:
      login_required: false
      write_protected: true

  # Admin operations
  - slot_id: 2
    label: "ADMIN"
    flags:
      login_required: true
      user_pin_change: true
```

### PIN Configuration

PINs can be configured in multiple ways (in order of precedence):

1. Environment variable: `KEYCHAIN_PIN`
2. Configuration file: `tokens[].pin`
3. Runtime via `C_Login()`

For security, avoid storing PINs in configuration files in production.

## Logging Configuration

Enable debug logging for troubleshooting:

```bash
export KEYCHAIN_DEBUG=true
export KEYCHAIN_LOG_FILE=/var/log/gokeychain-pkcs11.log
```

Log levels:
- `error`: Only errors
- `warn`: Warnings and errors
- `info`: General information
- `debug`: Detailed debugging information

## Performance Tuning

### Connection Pooling

For remote backends, configure connection pooling:

```yaml
pkcs11:
  mode: rest
  rest:
    base_url: https://localhost:8443
    # Maximum concurrent connections
    max_connections: 10
    # Keep connections alive
    keepalive_ms: 30000
```

### Timeout Configuration

Configure appropriate timeouts for your network:

```yaml
pkcs11:
  mode: grpc
  grpc:
    address: localhost:9443
    # Connection timeout
    connect_timeout_ms: 5000
    # Operation timeout
    timeout_ms: 30000
    # Keep-alive ping interval
    keepalive_ms: 30000
```
