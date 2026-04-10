# xKMS Daemon Configuration

This directory contains configuration files and examples for the xkms daemon (`xkmsd`).

## Files

- `xkmsd.yaml.example` - Comprehensive example configuration with all available options
- `xkmsd.yaml` - Minimal working configuration for development/testing
- `xkmsd.service` - Systemd service unit file
- `README.md` - This file

## Quick Start

### Development/Testing

1. Copy the minimal config:
   ```bash
   cp configs/xkmsd.yaml /tmp/xkmsd-dev.yaml
   ```

2. Start the daemon:
   ```bash
   ./bin/xkmsd -c /tmp/xkmsd-dev.yaml
   ```

### Production Installation

1. Create the xkms user and group:
   ```bash
   sudo useradd --system --no-create-home --shell /bin/false xkms
   ```

2. Create required directories:
   ```bash
   sudo mkdir -p /etc/xkms /var/lib/xkms /var/run/xkms
   sudo chown xkms:xkms /var/lib/xkms /var/run/xkms
   sudo chmod 750 /var/lib/xkms /var/run/xkms
   ```

3. Copy and customize the configuration:
   ```bash
   sudo cp configs/xkmsd.yaml.example /etc/xkms/xkmsd.yaml
   sudo chown xkms:xkms /etc/xkms/xkmsd.yaml
   sudo chmod 640 /etc/xkms/xkmsd.yaml
   sudo vi /etc/xkms/xkmsd.yaml  # Customize as needed
   ```

4. Install the binary:
   ```bash
   sudo cp bin/xkmsd /usr/bin/xkmsd
   sudo chown root:root /usr/bin/xkmsd
   sudo chmod 755 /usr/bin/xkmsd
   ```

5. Install and enable the systemd service:
   ```bash
   sudo cp configs/xkmsd.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable xkmsd
   sudo systemctl start xkmsd
   ```

6. Check the service status:
   ```bash
   sudo systemctl status xkmsd
   sudo journalctl -u xkmsd -f
   ```

## Command Line Options

```
xkmsd [OPTIONS]

Options:
  -c, --config PATH        Path to configuration file (default: /etc/xkms/xkmsd.yaml)
  -d, --daemon             Run as daemon (deprecated - use systemd instead)
  --pid-file PATH          Write PID to file
  --version                Show version information
```

## Environment Variables

The following environment variables can override configuration file settings:

### Server Configuration
- `XKMS_CONFIG` - Configuration file path
- `XKMS_HOST` - Server host address
- `XKMS_REST_PORT` - REST API port
- `XKMS_GRPC_PORT` - gRPC server port
- `XKMS_QUIC_PORT` - QUIC server port
- `XKMS_MCP_PORT` - MCP server port

### Unix Socket Configuration
- `XKMS_SOCKET_PATH` - Unix socket file path
- `XKMS_SOCKET_MODE` - Unix socket permissions (e.g., "0660")
- `XKMS_UNIX_PROTOCOL` - Unix socket protocol ("grpc" or "http")

### Logging Configuration
- `XKMS_LOG_LEVEL` - Log level (debug, info, warn, error, fatal)
- `XKMS_LOG_FORMAT` - Log format (json, text, console)

### Storage Configuration
- `XKMS_DATA_DIR` - Data storage directory

### RNG Configuration
- `XKMS_RNG_MODE` - RNG mode (auto, software, tpm2, pkcs11)
- `XKMS_RNG_FALLBACK` - RNG fallback mode

## Signal Handling

The daemon responds to the following signals:

- `SIGTERM` / `SIGINT` - Graceful shutdown
- `SIGHUP` - Reload configuration (currently supports logging config only)

### Reloading Configuration

To reload the configuration without restarting:

```bash
sudo systemctl reload xkmsd
# or
sudo kill -HUP $(cat /var/run/xkmsd.pid)
```

**Note:** Currently only logging configuration can be reloaded. Changes to protocols, backends, or network settings require a full restart:

```bash
sudo systemctl restart xkmsd
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
sudo systemctl status xkmsd
```

### View logs
```bash
sudo journalctl -u xkmsd -f
```

### Test connectivity
```bash
# Unix socket (gRPC)
grpcurl -unix /var/run/xkms/xkms.sock list

# REST API
curl http://localhost:8443/health
```

### Validate configuration
```bash
xkmsd --config /etc/xkms/xkmsd.yaml --version
```

### Permission issues

If you encounter permission errors:

```bash
# Check directory permissions
ls -la /var/lib/xkms /var/run/xkms

# Check socket permissions
ls -la /var/run/xkms/xkms.sock

# Verify user can access socket
sudo -u xkms stat /var/run/xkms/xkms.sock
```

## Security Considerations

1. **File Permissions** - Ensure proper permissions on config files and data directories
2. **Unix Socket** - The socket should be readable/writable by the xkms group only
3. **TLS Certificates** - Use proper TLS certificates for network protocols
4. **Authentication** - Enable authentication for network-exposed protocols
5. **Rate Limiting** - Enable rate limiting to prevent abuse
6. **Systemd Hardening** - The provided service file includes security hardening options

## See Also

- Main project README: `/README.md`
- Example configuration: `xkmsd.yaml.example`
- API documentation: `/docs/`
