# Keychain Daemon Configuration

This directory contains configuration files and examples for the keychain daemon (`keychaind`).

## Files

- `keychaind.yaml.example` - Comprehensive example configuration with all available options
- `keychaind.yaml` - Minimal working configuration for development/testing
- `keychaind.service` - Systemd service unit file
- `README.md` - This file

## Quick Start

### Development/Testing

1. Copy the minimal config:
   ```bash
   cp configs/keychaind.yaml /tmp/keychaind-dev.yaml
   ```

2. Start the daemon:
   ```bash
   ./bin/keychaind -c /tmp/keychaind-dev.yaml
   ```

### Production Installation

1. Create the keychain user and group:
   ```bash
   sudo useradd --system --no-create-home --shell /bin/false keychain
   ```

2. Create required directories:
   ```bash
   sudo mkdir -p /etc/keychain /var/lib/keychain /var/run/keychain
   sudo chown keychain:keychain /var/lib/keychain /var/run/keychain
   sudo chmod 750 /var/lib/keychain /var/run/keychain
   ```

3. Copy and customize the configuration:
   ```bash
   sudo cp configs/keychaind.yaml.example /etc/keychain/keychaind.yaml
   sudo chown keychain:keychain /etc/keychain/keychaind.yaml
   sudo chmod 640 /etc/keychain/keychaind.yaml
   sudo vi /etc/keychain/keychaind.yaml  # Customize as needed
   ```

4. Install the binary:
   ```bash
   sudo cp bin/keychaind /usr/bin/keychaind
   sudo chown root:root /usr/bin/keychaind
   sudo chmod 755 /usr/bin/keychaind
   ```

5. Install and enable the systemd service:
   ```bash
   sudo cp configs/keychaind.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable keychaind
   sudo systemctl start keychaind
   ```

6. Check the service status:
   ```bash
   sudo systemctl status keychaind
   sudo journalctl -u keychaind -f
   ```

## Command Line Options

```
keychaind [OPTIONS]

Options:
  -c, --config PATH        Path to configuration file (default: /etc/keychain/keychaind.yaml)
  -d, --daemon             Run as daemon (deprecated - use systemd instead)
  --pid-file PATH          Write PID to file
  --version                Show version information
```

## Environment Variables

The following environment variables can override configuration file settings:

### Server Configuration
- `KEYCHAIN_CONFIG` - Configuration file path
- `KEYCHAIN_HOST` - Server host address
- `KEYCHAIN_REST_PORT` - REST API port
- `KEYCHAIN_GRPC_PORT` - gRPC server port
- `KEYCHAIN_QUIC_PORT` - QUIC server port
- `KEYCHAIN_MCP_PORT` - MCP server port

### Unix Socket Configuration
- `KEYCHAIN_SOCKET_PATH` - Unix socket file path
- `KEYCHAIN_SOCKET_MODE` - Unix socket permissions (e.g., "0660")
- `KEYCHAIN_UNIX_PROTOCOL` - Unix socket protocol ("grpc" or "http")

### Logging Configuration
- `KEYCHAIN_LOG_LEVEL` - Log level (debug, info, warn, error, fatal)
- `KEYCHAIN_LOG_FORMAT` - Log format (json, text, console)

### Storage Configuration
- `KEYCHAIN_DATA_DIR` - Data storage directory

### RNG Configuration
- `KEYCHAIN_RNG_MODE` - RNG mode (auto, software, tpm2, pkcs11)
- `KEYCHAIN_RNG_FALLBACK` - RNG fallback mode

## Signal Handling

The daemon responds to the following signals:

- `SIGTERM` / `SIGINT` - Graceful shutdown
- `SIGHUP` - Reload configuration (currently supports logging config only)

### Reloading Configuration

To reload the configuration without restarting:

```bash
sudo systemctl reload keychaind
# or
sudo kill -HUP $(cat /var/run/keychaind.pid)
```

**Note:** Currently only logging configuration can be reloaded. Changes to protocols, backends, or network settings require a full restart:

```bash
sudo systemctl restart keychaind
```

## Configuration Options

### Protocols

Enable/disable different communication protocols:

- `unix` - Unix domain socket (recommended for local access)
- `rest` - REST API over HTTP/HTTPS
- `grpc` - gRPC over TCP
- `quic` - QUIC/HTTP3
- `mcp` - Model Context Protocol (JSON-RPC)

### Unix Socket Protocol

The Unix socket can use either:
- `grpc` - gRPC protocol (default, more efficient)
- `http` - HTTP protocol (for REST-like access)

### Backends

Supported key storage backends:

- `software` - Software-based PKCS#8 keys (default)
- `pkcs8` - Explicit PKCS#8 backend
- `tpm2` - TPM 2.0 hardware
- `pkcs11` - PKCS#11 HSMs (YubiKey, SoftHSM, etc.)
- `awskms` - AWS Key Management Service
- `gcpkms` - Google Cloud KMS
- `azurekv` - Azure Key Vault
- `vault` - HashiCorp Vault

### Security Features

- **TLS/mTLS** - Mutual TLS authentication
- **Rate Limiting** - Request rate limiting per client
- **Authentication** - API key, JWT, or mTLS auth
- **Audit Logging** - Structured JSON logging
- **Health Checks** - Kubernetes-compatible health endpoints

## Troubleshooting

### Check service status
```bash
sudo systemctl status keychaind
```

### View logs
```bash
sudo journalctl -u keychaind -f
```

### Test connectivity
```bash
# Unix socket (gRPC)
grpcurl -unix /var/run/keychain/keychain.sock list

# REST API
curl http://localhost:8443/health
```

### Validate configuration
```bash
keychaind --config /etc/keychain/keychaind.yaml --version
```

### Permission issues

If you encounter permission errors:

```bash
# Check directory permissions
ls -la /var/lib/keychain /var/run/keychain

# Check socket permissions
ls -la /var/run/keychain/keychain.sock

# Verify user can access socket
sudo -u keychain stat /var/run/keychain/keychain.sock
```

## Security Considerations

1. **File Permissions** - Ensure proper permissions on config files and data directories
2. **Unix Socket** - The socket should be readable/writable by the keychain group only
3. **TLS Certificates** - Use proper TLS certificates for network protocols
4. **Authentication** - Enable authentication for network-exposed protocols
5. **Rate Limiting** - Enable rate limiting to prevent abuse
6. **Systemd Hardening** - The provided service file includes security hardening options

## See Also

- Main project README: `/README.md`
- Example configuration: `keychaind.yaml.example`
- API documentation: `/docs/`
