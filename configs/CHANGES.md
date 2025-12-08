# Keychain Daemon Configuration Updates

## Summary

Updated the keychain daemon (`keychaind`) to properly support daemon operation with comprehensive configuration file support, signal handling, and systemd integration.

## Changes Made

### 1. Updated `cmd/server/main.go`

Added the following features:

- **Configuration flag support**:
  - `--config` / `-c` - Path to configuration file (default: `/etc/keychain/keychaind.yaml`)
  - `--daemon` / `-d` - Run as daemon flag (for compatibility)
  - `--pid-file` - PID file path support
  - `--version` - Show version information

- **Environment variable support**:
  - `KEYCHAIN_CONFIG` - Override config file path

- **Signal handling**:
  - `SIGTERM` / `SIGINT` - Graceful shutdown
  - `SIGHUP` - Configuration reload

- **PID file management**:
  - Automatic creation and cleanup of PID files
  - Directory creation if needed

- **Configuration reload**:
  - Runtime configuration reload on SIGHUP
  - Validation before applying new config
  - Error handling for failed reloads

### 2. Updated `internal/config/config.go`

Added and enhanced:

- **UnixConfig.Protocol field**:
  - Allows choosing between "grpc" or "http" for Unix socket
  - Default: "grpc"
  - Validated in `Validate()` method

- **Environment variable support**:
  - `KEYCHAIN_SOCKET_PATH` - Override Unix socket path
  - `KEYCHAIN_SOCKET_MODE` - Override Unix socket permissions
  - `KEYCHAIN_UNIX_PROTOCOL` - Override Unix socket protocol
  - All new `KEYCHAIN_*` prefixed variables
  - Backward compatibility with `KEYSTORE_*` variables

- **Enhanced validation**:
  - Unix socket protocol validation
  - Comprehensive error messages

### 3. Updated `internal/server/server.go`

- **Added mutex field** (`mu sync.RWMutex`):
  - Thread-safe configuration reloading
  - Protects server state during updates

### 4. Created `internal/server/reload.go`

New file implementing configuration reload functionality:

- **`Reload(cfg *config.Config)` method**:
  - Safely reloads server configuration
  - Currently supports logging configuration changes
  - Thread-safe with mutex locking
  - Validates configuration before applying

- **`reloadLogging(cfg *config.Config)` method**:
  - Updates logger instance with new configuration
  - Logs configuration changes

### 5. Created Configuration Files

#### `configs/keychaind.yaml.example`
Comprehensive example configuration with:
- All available server options
- Detailed comments for each setting
- All protocol configurations
- All backend configurations
- TLS/mTLS settings
- Authentication options
- Rate limiting configuration
- RNG configuration
- Environment variable documentation

#### `configs/keychaind.yaml`
Minimal working configuration for development/testing:
- Software backend only
- Unix socket enabled
- Temporary file paths for testing
- Simplified settings for quick start

#### `configs/keychaind.service`
Production-ready systemd service file with:
- Proper service configuration
- Security hardening (NoNewPrivileges, ProtectSystem, etc.)
- Resource limits
- Directory management (RuntimeDirectory, StateDirectory, etc.)
- Reload support via SIGHUP
- Auto-restart on failure
- Proper user/group isolation

#### `configs/README.md`
Complete documentation including:
- Quick start guide
- Production installation instructions
- Command-line options reference
- Environment variables reference
- Signal handling documentation
- Configuration reload instructions
- Troubleshooting guide
- Security considerations

#### `configs/install.sh`
Installation script that:
- Creates system user and group
- Creates required directories with proper permissions
- Installs binary to `/usr/bin/keychaind`
- Installs configuration to `/etc/keychain/`
- Installs systemd service
- Provides post-installation instructions

## Features

### Signal Handling

- **SIGTERM / SIGINT**: Graceful shutdown
  - Stops all protocol servers
  - Closes all backends
  - Waits for in-flight requests
  - Clean resource cleanup

- **SIGHUP**: Configuration reload
  - Reloads configuration file
  - Validates new configuration
  - Applies changes without restart
  - Currently supports: logging configuration
  - Future: TLS certificate reload, rate limit updates

### Environment Variables

All configuration can be overridden via environment variables:

**Server:**
- `KEYCHAIN_HOST`
- `KEYCHAIN_REST_PORT`
- `KEYCHAIN_GRPC_PORT`
- `KEYCHAIN_QUIC_PORT`
- `KEYCHAIN_MCP_PORT`

**Unix Socket:**
- `KEYCHAIN_SOCKET_PATH`
- `KEYCHAIN_SOCKET_MODE`
- `KEYCHAIN_UNIX_PROTOCOL`

**Logging:**
- `KEYCHAIN_LOG_LEVEL`
- `KEYCHAIN_LOG_FORMAT`

**Storage:**
- `KEYCHAIN_DATA_DIR`

**RNG:**
- `KEYCHAIN_RNG_MODE`
- `KEYCHAIN_RNG_FALLBACK`

### Unix Socket Protocol Support

The Unix socket can now use either:
- **gRPC** (default) - More efficient, native protobuf support
- **HTTP** - REST-like access, easier debugging

Configure via `unix.protocol` in config file or `KEYCHAIN_UNIX_PROTOCOL` environment variable.

### Production Deployment

The systemd service file includes:

**Security Hardening:**
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `ProtectKernelTunables=true`
- `ProtectControlGroups=true`
- `RestrictRealtime=true`
- `RestrictNamespaces=true`
- `RestrictSUIDSGID=true`
- `LockPersonality=true`
- System call filtering

**Resource Management:**
- File descriptor limits
- Process limits
- Automatic directory creation
- Proper file permissions

**Reliability:**
- Automatic restart on failure
- Graceful shutdown support
- Health check integration

## Usage Examples

### Development

```bash
# Build the binary
go build -o bin/keychaind ./cmd/server

# Run with development config
./bin/keychaind -c configs/keychaind.yaml

# Run with custom config and PID file
./bin/keychaind --config /tmp/my-config.yaml --pid-file /tmp/keychaind.pid
```

### Production Installation

```bash
# Install using the provided script
sudo ./configs/install.sh

# Or manually:
sudo useradd --system --no-create-home keychain
sudo mkdir -p /etc/keychain /var/lib/keychain /var/run/keychain
sudo cp bin/keychaind /usr/bin/
sudo cp configs/keychaind.yaml.example /etc/keychain/keychaind.yaml
sudo cp configs/keychaind.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now keychaind
```

### Configuration Reload

```bash
# Edit configuration
sudo vi /etc/keychain/keychaind.yaml

# Reload configuration
sudo systemctl reload keychaind

# Or send SIGHUP directly
sudo kill -HUP $(cat /var/run/keychaind.pid)
```

## Testing

Build and test the daemon:

```bash
# Build
go build -o bin/keychaind ./cmd/server

# Test version
./bin/keychaind --version

# Test with config
./bin/keychaind -c configs/keychaind.yaml

# Test in background with PID file
./bin/keychaind -c configs/keychaind.yaml --pid-file /tmp/keychaind.pid &

# Reload configuration
kill -HUP $(cat /tmp/keychaind.pid)

# Shutdown
kill -TERM $(cat /tmp/keychaind.pid)
```

## Backward Compatibility

- Maintains support for legacy `KEYSTORE_*` environment variables
- Existing configuration files continue to work
- No breaking changes to existing functionality
- New features are opt-in via configuration

## Future Enhancements

Potential improvements for config reload:

1. **TLS Certificate Reload**
   - Hot reload of TLS certificates
   - No downtime for certificate updates

2. **Rate Limit Updates**
   - Dynamic rate limit adjustments
   - Per-client rate limit configuration

3. **Backend Configuration**
   - Add/remove backends at runtime
   - Update backend credentials

4. **Protocol Enable/Disable**
   - Start/stop protocol servers dynamically
   - Port changes without restart

## Files Modified

- `cmd/server/main.go` - Main daemon entry point
- `internal/config/config.go` - Configuration loading and validation
- `internal/server/server.go` - Server struct (added mutex)
- `internal/server/reload.go` - Configuration reload implementation (new)

## Files Created

- `configs/keychaind.yaml.example` - Example configuration
- `configs/keychaind.yaml` - Development configuration
- `configs/keychaind.service` - Systemd service file
- `configs/README.md` - Configuration documentation
- `configs/install.sh` - Installation script
- `configs/CHANGES.md` - This file
