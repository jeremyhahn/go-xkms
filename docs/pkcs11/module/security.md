# Security Considerations

This document outlines security considerations for deploying and using the PKCS#11 provider module.

## Authentication

### Unix Socket Mode

The Unix backend uses kernel-level authentication via SO_PEERCRED:

```c
// Server extracts peer credentials from kernel
struct ucred creds;
socklen_t len = sizeof(creds);
getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &creds, &len);

// Kernel-verified: UID, GID, PID of connecting process
printf("UID=%d GID=%d PID=%d\n", creds.uid, creds.gid, creds.pid);
```

Security properties:
- **Zero-trust authentication**: Credentials verified by kernel, not application
- **No credential transmission**: No tokens or passwords sent over socket
- **Unforgeable**: Process cannot impersonate another UID/GID
- **Revocation**: Closing socket immediately revokes access

Access control:
```yaml
# Configure allowed UIDs/GIDs
unix:
  allowed_uids: [1000, 1001]
  allowed_gids: [1000, "keychain-users"]
  # Or use file permissions
  socket_mode: 0660
  socket_group: keychain-users
```

### Remote Modes (REST, gRPC, QUIC)

Remote backends require TLS with mutual authentication:

```yaml
rest:
  base_url: https://keychain.example.com:8443
  tls_ca_file: /etc/gokeychain/ca.crt
  tls_cert_file: /etc/gokeychain/client.crt
  tls_key_file: /etc/gokeychain/client.key
```

Requirements:
- TLS 1.3 required for all remote connections
- Client certificate authentication mandatory
- Server certificate pinning recommended
- Never set `tls_insecure: true` in production

### PIN Management

PKCS#11 PINs are used for user and SO authentication:

**Best practices:**
- Never store PINs in configuration files
- Use environment variables or interactive prompt
- Implement PIN attempt limiting
- Consider hardware-backed PIN storage

```bash
# Use environment variable (cleared after read)
export KEYCHAIN_PIN="..."
pkcs11-tool --module $P11_MODULE --login --list-objects
unset KEYCHAIN_PIN
```

## Thread Safety

The module implements thread-safe access:

| Component | Protection |
|-----------|------------|
| Global state | Mutex protected |
| Session state | Per-session lock |
| Handle table | Lock-free reads, mutex writes |
| Backend calls | Serialized per-session |

Thread safety modes (from PKCS#11 spec):
- `CKF_OS_LOCKING_OK`: Module uses OS primitives (pthread)
- Application-provided mutex functions
- Single-threaded mode (no locking)

```c
CK_C_INITIALIZE_ARGS args = {
    .flags = CKF_OS_LOCKING_OK
};
C_Initialize(&args);
```

## Memory Protection

### Sensitive Data Handling

The module protects sensitive data in memory:

```c
// Clear sensitive data after use
void keychain_secure_zero(void* ptr, size_t len) {
    volatile unsigned char* p = ptr;
    while (len--) *p++ = 0;
}

// Example: Clear PIN after use
char pin[64];
// ... use pin ...
keychain_secure_zero(pin, sizeof(pin));
```

### Memory Allocation

- No internal allocations exposed to application
- All buffers freed by module functions
- Two-call pattern prevents buffer overflows

## Input Validation

All inputs are validated:

| Input | Validation |
|-------|------------|
| Key IDs | Length limits, character restrictions |
| Key sizes | Allowed values only (2048, 3072, 4096) |
| Curves | Allowed curves only |
| Buffers | NULL checks, size validation |
| Handles | Validity checks |

## Error Handling

Errors are designed to prevent information leakage:

- Generic errors for authentication failures
- No timing differences between valid/invalid credentials
- Constant-time comparisons for sensitive values

## Audit Logging

Enable audit logging for security monitoring:

```yaml
logging:
  audit: true
  audit_file: /var/log/gokeychain/audit.log
  # Log successful operations
  log_success: true
  # Log failed operations
  log_failure: true
```

Logged events:
- Session open/close
- Login attempts (success/failure)
- Key generation
- Signing operations
- Object deletion

## Network Security

### TLS Configuration

Recommended TLS settings:

```yaml
tls:
  # Minimum version
  min_version: "1.3"

  # Cipher suites (TLS 1.3 only)
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256

  # OCSP stapling
  ocsp_stapling: true

  # Certificate rotation
  cert_rotation_days: 30
```

### Firewall Recommendations

```bash
# Allow only specific IPs for remote access
iptables -A INPUT -p tcp --dport 8443 -s 10.0.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP

# Rate limiting
iptables -A INPUT -p tcp --dport 8443 \
  -m conntrack --ctstate NEW \
  -m limit --limit 10/minute --limit-burst 20 \
  -j ACCEPT
```

## File System Security

### Socket Permissions

```bash
# Secure socket directory
sudo mkdir -p /var/run/keychain
sudo chown root:keychain-users /var/run/keychain
sudo chmod 750 /var/run/keychain

# Socket created with restricted permissions
# socket_mode: 0660 in config
```

### Configuration File Permissions

```bash
# Protect configuration files
sudo chown root:keychain /etc/gokeychain/pkcs11.yaml
sudo chmod 640 /etc/gokeychain/pkcs11.yaml

# Protect TLS keys
sudo chmod 600 /etc/gokeychain/*.key
```

## Library Loading Security

### Embedded Mode

The module uses `dlopen()` to load libkeychain.so:

```c
// Only load from secure paths
const char* allowed_paths[] = {
    "/usr/lib/libkeychain.so",
    "/usr/local/lib/libkeychain.so",
    NULL
};
```

Recommendations:
- Use absolute paths only
- Verify library signature if possible
- Set `LD_LIBRARY_PATH` restrictions

## Denial of Service Protection

### Connection Limits

```yaml
limits:
  # Maximum concurrent sessions
  max_sessions: 100
  # Maximum objects per session
  max_objects: 10000
  # Operation timeout
  timeout_ms: 30000
  # Rate limiting
  max_ops_per_minute: 1000
```

### Resource Limits

```bash
# Limit process resources
ulimit -n 1024  # File descriptors
ulimit -m 1048576  # Memory (KB)
```

## Security Checklist

Before production deployment:

- [ ] TLS 1.3 enabled for all remote connections
- [ ] Client certificate authentication configured
- [ ] PINs not stored in configuration files
- [ ] Socket permissions restricted (Unix mode)
- [ ] Audit logging enabled
- [ ] Rate limiting configured
- [ ] Firewall rules in place
- [ ] Library paths restricted
- [ ] Configuration files protected
- [ ] Regular security updates applied

## Vulnerability Reporting

Report security vulnerabilities to: security@example.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
