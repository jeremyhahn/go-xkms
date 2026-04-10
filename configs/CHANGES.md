# xKMS Daemon Configuration Updates

## Summary

Updated the xkms daemon (`xkmsd`) to properly support daemon operation with comprehensive configuration file support, signal handling, and systemd integration.

## Changes Made

### 1. Updated `cmd/server/main.go`

Added the following features:

- **Configuration flag support**:
  - `--config` / `-c` - Path to configuration file (default: `/etc/xkms/xkmsd.yaml`)
  - `--daemon` / `-d` - Run as daemon flag (for compatibility)
  - `--pid-file` - PID file path support
  - `--version` - Show version information

- **Environment variable support**:
  - `XKMS_CONFIG` - Override config file path

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
  - `XKMS_SOCKET_PATH` - Override Unix socket path
  - `XKMS_SOCKET_MODE` - Override Unix socket permissions
  - `XKMS_UNIX_PROTOCOL` - Override Unix socket protocol
  - All new `XKMS_*` prefixed variables
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

#### `configs/xkmsd.yaml.example`
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

#### `configs/xkmsd.yaml`
Minimal working configuration for development/testing:
- Software backend only
- Unix socket enabled
- Temporary file paths for testing
- Simplified settings for quick start

#### `configs/xkmsd.service`
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
- Installs binary to `/usr/bin/xkmsd`
- Installs configuration to `/etc/xkms/`
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
- `XKMS_HOST`
- `XKMS_REST_PORT`
- `XKMS_GRPC_PORT`
- `XKMS_QUIC_PORT`
- `XKMS_MCP_PORT`

**Unix Socket:**
- `XKMS_SOCKET_PATH`
- `XKMS_SOCKET_MODE`
- `XKMS_UNIX_PROTOCOL`

**Logging:**
- `XKMS_LOG_LEVEL`
- `XKMS_LOG_FORMAT`

**Storage:**
- `XKMS_DATA_DIR`

**RNG:**
- `XKMS_RNG_MODE`
- `XKMS_RNG_FALLBACK`

### Unix Socket Protocol Support

The Unix socket can now use either:
- **gRPC** (default) - More efficient, native protobuf support
- **HTTP** - REST-like access, easier debugging

Configure via `unix.protocol` in config file or `XKMS_UNIX_PROTOCOL` environment variable.

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
go build -o bin/xkmsd ./cmd/server

# Run with development config
./bin/xkmsd -c configs/xkmsd.yaml

# Run with custom config and PID file
./bin/xkmsd --config /tmp/my-config.yaml --pid-file /tmp/xkmsd.pid
```

### Production Installation

```bash
# Install using the provided script
sudo ./configs/install.sh

# Or manually:
sudo useradd --system --no-create-home xkms
sudo mkdir -p /etc/xkms /var/lib/xkms /var/run/xkms
sudo cp bin/xkmsd /usr/bin/
sudo cp configs/xkmsd.yaml.example /etc/xkms/xkmsd.yaml
sudo cp configs/xkmsd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xkmsd
```

### Configuration Reload

```bash
# Edit configuration
sudo vi /etc/xkms/xkmsd.yaml

# Reload configuration
sudo systemctl reload xkmsd

# Or send SIGHUP directly
sudo kill -HUP $(cat /var/run/xkmsd.pid)
```

## Testing

Build and test the daemon:

```bash
# Build
go build -o bin/xkmsd ./cmd/server

# Test version
./bin/xkmsd --version

# Test with config
./bin/xkmsd -c configs/xkmsd.yaml

# Test in background with PID file
./bin/xkmsd -c configs/xkmsd.yaml --pid-file /tmp/xkmsd.pid &

# Reload configuration
kill -HUP $(cat /tmp/xkmsd.pid)

# Shutdown
kill -TERM $(cat /tmp/xkmsd.pid)
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

- `configs/xkmsd.yaml.example` - Example configuration
- `configs/xkmsd.yaml` - Development configuration
- `configs/xkmsd.service` - Systemd service file
- `configs/README.md` - Configuration documentation
- `configs/install.sh` - Installation script
- `configs/CHANGES.md` - This file
