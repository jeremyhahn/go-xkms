# Security Considerations

This document outlines security considerations for deploying and using the PKCS#11 provider module.

## Access Control Model

Every object-manager call that an application can reach takes an `AccessContext{Session, LoggedIn, ReadWrite}`
(`pkg/pkcs11/module/object.go`), built fresh per call from the live session via `NewAccessContext`. It carries the
two facts PKCS#11 v3.2 needs to authorize an object operation: whether the normal user is logged in, and whether
the session was opened read/write.

- **`GetObjectFor(ctx, handle)` is the mandatory gate for every application-driven lookup** -- key resolution for a
  crypto operation, attribute access, wrapping, `FindObjects`. `GetObject(handle)` performs no access check at all
  and exists only for internal callers with no session context, such as restoring persisted objects at startup or
  continuing an operation whose key was already validated at `*Init` time. A path that serves an application
  request must not call `GetObject` directly.
- **A private object (`CKA_PRIVATE=TRUE`) is invisible to a session that has not authenticated.** `GetObjectFor`
  and `FindObjectsInit` both return `CKR_OBJECT_HANDLE_INVALID` for a private object when the caller is not logged
  in -- the same code a nonexistent handle produces, so an unauthenticated session cannot distinguish "no such
  object" from "object exists but you may not see it."
- **`CKF_LOGIN_REQUIRED` is enforced before any key-bearing operation.** `resolveOperationKey` calls
  `requireLogin`, which checks the token's `CKF_LOGIN_REQUIRED` flag and returns `CKR_USER_NOT_LOGGED_IN` if the
  session has not authenticated as either the normal user or the SO.
- **An absent key-usage attribute is a denial, not an implicit grant.** `resolveOperationKey` maps each operation
  category to the attribute that must be `CK_TRUE` for the key to be usable with it (`CKA_SIGN` for signing,
  `CKA_VERIFY` for verification, `CKA_ENCRYPT`/`CKA_DECRYPT`), and returns `CKR_KEY_FUNCTION_NOT_PERMITTED` unless
  that attribute is explicitly set. A key created without an opinion on `CKA_SIGN` cannot sign.

## Known Limitation: Objects Are Not Slot-Scoped

The `ObjectManager` is currently shared across every slot the module exposes: an object does not carry a slot
identity. On a single-slot configuration this is unobservable, but on a multi-slot module a session opened
against one slot can find and use objects created against another slot -- `C_InitToken` on one slot also destroys
every destroyable object across all slots (see `destroyTokenObjects` in `pkg/pkcs11/module/module.go`). Fixing
this requires threading a slot identity through object creation, restore-from-storage, and the PIV object-loading
path, none of which currently carry one. Deployments that need real slot isolation should run one module instance
per slot until this is addressed.

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
  allowed_gids: [1000, "xkms-users"]
  # Or use file permissions
  socket_mode: 0660
  socket_group: xkms-users
```

### Remote Modes (REST, gRPC, QUIC)

Remote backends require TLS with mutual authentication:

```yaml
rest:
  base_url: https://xkms.example.com:8443
  tls_ca_file: /etc/goxkms/ca.crt
  tls_cert_file: /etc/goxkms/client.crt
  tls_key_file: /etc/goxkms/client.key
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
export XKMS_PIN="..."
pkcs11-tool --module $P11_MODULE --login --list-objects
unset XKMS_PIN
```

#### Unified PIN Coordination

When running alongside the xkey FIDO2 daemon in unified PIN mode (the default),
the PKCS#11 token User PIN is automatically synchronized with FIDO2 PIN changes.
PIN updates originating from Chrome WebAuthn prompts or the CLI propagate to the
PKCS#11 token without manual intervention.

How it works:

- The `PKCS11PINSubscriber` registers with the `PINCoordinator` and listens for
  PIN change notifications.
- On receiving a raw PIN notification the subscriber calls
  `token.SetUserPin(rawPIN)`, which stores `SHA-256(rawPIN)` as the token's
  User PIN.
- Hash-only notifications (e.g., from an SO PIN reset where the raw PIN is
  unavailable) are skipped gracefully because the PKCS#11 token requires the
  raw PIN string to compute its own hash.
- Disable this behavior by starting the daemon with `--unified-pin=false`.

See [Unified PIN Architecture](../../architecture/pin-architecture.md) for
details.

#### PIN Storage and Lockout

PINs are never stored or compared in the clear. `hashPin` (`pkg/pkcs11/module/session.go`) derives a salted
Argon2id verifier -- a fresh random 16-byte salt per PIN, self-describing output (version, salt, derived key) so
the salt does not need a second stored field. Verification goes through `verifyPin`, which recovers the salt from
the stored verifier and compares in constant time; two PINs are never compared by re-hashing one and matching
bytes, since two `hashPin` calls on the same PIN produce different output.

A PIN locks after `MaxPINAttempts` (3) consecutive failed attempts, tracked independently for the SO and the
normal user. A locked PIN returns `CKR_PIN_LOCKED` on every subsequent attempt until reset by an authorized party
(a successful `C_SetPIN`/`C_InitPIN`, or `C_InitToken` for the SO PIN). The failure counts are also published
through `C_GetTokenInfo`: `CKF_USER_PIN_COUNT_LOW` / `CKF_USER_PIN_FINAL_TRY` / `CKF_USER_PIN_LOCKED` and their
`CKF_SO_PIN_*` counterparts reflect the live counters.

**The failure counts are persisted.** Both counters are written to the module's storage backend on every failed
attempt and restored at `C_Initialize`, so a lockout is not cleared by `C_Finalize` followed by a fresh
`C_Initialize`. Surviving a *process restart* additionally requires the file storage backend
(`XKMS_PKCS11_STORAGE_TYPE=file`); with the in-memory default the counters go with the process. Only the counts
are stored -- lock state is recomputed from them, so there is no separate flag to fall out of step.

`C_InitToken` on a token that is already initialized requires the *existing* SO PIN before it will proceed --
without this check, any local caller could seize a provisioned token by supplying a new PIN of its choosing.
Reinitialization also destroys every object with `CKA_DESTROYABLE=TRUE` on the token and clears the user PIN, per
PKCS#11 v3.2 §5.5.7.

## Attribute Protection

Object attributes are protected independently of the session-level access rules above; see
[Access Control Model](#access-control-model) for the object-visibility rules that apply before these come into
play.

- **A sensitive attribute is withheld whenever the object is `CKA_SENSITIVE=TRUE` *or* `CKA_EXTRACTABLE=FALSE`.**
  `GetAttributeValue` checks both conditions independently: an unextractable key is protected even when
  `CKA_SENSITIVE` is `CK_FALSE`. `CKA_VALUE`, `CKA_PRIVATE_EXPONENT`, and the RSA CRT components
  (`CKA_PRIME_1`/`CKA_PRIME_2`/`CKA_EXPONENT_1`/`CKA_EXPONENT_2`/`CKA_COEFFICIENT`) are the sensitive set
  (`IsSensitiveAttribute` in `pkg/pkcs11/module/object.go`). A withheld attribute returns
  `CKR_ATTRIBUTE_SENSITIVE` and reports `CK_UNAVAILABLE_INFORMATION` per PKCS#11 v3.2 §5.7.5 -- the request never
  fails outright, so a caller reading a mixed template still gets every attribute it is entitled to.
- **Four boolean attributes are one-way.** `CKA_SENSITIVE` and `CKA_WRAP_WITH_TRUSTED` may only transition
  `CK_FALSE` → `CK_TRUE`; `CKA_EXTRACTABLE` and `CKA_COPYABLE` only `CK_TRUE` → `CK_FALSE` (PKCS#11 v3.2 Table 13
  footnote 11, Table 17). Both `SetAttributeValue` and `CopyObject` reject the reverse transition with
  `CKR_ATTRIBUTE_READ_ONLY`; allowing it would let a caller strip protection from live key material.
- **`CKA_TRUSTED` can only be set to `CK_TRUE` by the Security Officer** (v3.2 Table 13 footnote 10). Any other
  attempt, and any attempt to retract an already-true value, is `CKR_ATTRIBUTE_READ_ONLY`. The rule is enforced at
  one choke point covering every creation path -- `C_CreateObject`, `C_GenerateKey`, `C_GenerateKeyPair`,
  `C_DeriveKey`, `C_UnwrapKey` and the KEM operations -- as well as `C_CopyObject` and `C_SetAttributeValue`.
  A trusted object defaults to `CKA_PRIVATE=CK_FALSE`, a token-specific default Table 17 permits: the SO cannot
  reach private objects (§4.2), so without it the only role allowed to create a trusted key would be the one role
  forbidden to create it. An explicit `CKA_PRIVATE` in the caller's template always wins.
- **Most attributes are read-only after creation**, including `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_MODULUS`,
  `CKA_PUBLIC_EXPONENT`, `CKA_EC_PARAMS`/`CKA_EC_POINT`, and `CKA_UNIQUE_ID`. `CKA_TOKEN`, `CKA_PRIVATE`,
  `CKA_MODIFIABLE`, and `CKA_DESTROYABLE` are also read-only via `C_SetAttributeValue`, but PKCS#11 v3.2 §4.1.1
  permits `C_CopyObject` to change them -- the copy is a new object, not a mutation of the original -- so they
  are tracked separately as copy-modifiable.
- **Protection defaults are the token's choice, and the token chooses protection.** A creation template that
  names neither `CKA_SENSITIVE` nor `CKA_EXTRACTABLE` produces `CKA_SENSITIVE=CK_TRUE` and
  `CKA_EXTRACTABLE=CK_FALSE`. Table 30 gives `CKA_EXTRACTABLE` no default and footnote 9 makes it
  "token-specific, and may depend on the values of other attributes", so the choice is the token's to make; both
  attributes are one-way ratchets (footnotes 11 and 12), so defaulting to the weaker value would spend a
  transition the application still had, while defaulting to the stronger leaves it free to ask for less in its
  own template. SoftHSM2 behaves the same way -- `pkcs11-tool --keygen --key-type aes:32` with a bare template
  yields a key reporting "never extractable" whose `CKA_VALUE` reads back `CKR_ATTRIBUTE_SENSITIVE`.
- **`CKA_SENSITIVE` is recorded on the daemon, not only on the module's object.** The module keeps the attribute
  locally so `C_GetAttributeValue` can answer without a round trip, but that store is client-side state. The
  key's record in xkmsd carries its own copy, fixed at generation, and `ExportKeyMaterial` refuses a key marked
  sensitive on the strength of that copy (`ErrKeySensitive`). Editing the module's local store therefore does not
  make a sensitive key readable. Enforcement sits in the service layer rather than in each backend, because every
  backend implementing the import/export seam can physically produce the bytes and one that forgot the check
  would become the way around it. Symmetric key records use metadata schema v2; a schema v1 record predates the
  field and is read as **sensitive**, since supplying the weaker value for an attribute that was never recorded
  is the one direction footnote 11 forbids.
- **A mechanism is refused when the key is the wrong type for it.** Every `C_*Init` compares the key's
  `CKA_KEY_TYPE` against the mechanism and answers `CKR_KEY_TYPE_INCONSISTENT` on a mismatch -- an RSA key passed
  to `CKM_AES_GCM`, an ECDSA key to `CKM_EDDSA`, or any asymmetric key to an HMAC mechanism, which v3.2 restricts
  to generic secret keys and the digest's own HMAC key type. The check covers unadvertised mechanisms too, since
  those still reach `C_*Init`.
- **The token alone computes provenance attributes.** `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_NEVER_EXTRACTABLE`, `CKA_KEY_GEN_MECHANISM`, and `CKA_UNIQUE_ID` can never be supplied by a caller in any
  creation template; doing so returns `CKR_ATTRIBUTE_READ_ONLY` immediately rather than silently accepting a
  forged claim such as "this key was generated on the token."

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
void xkms_secure_zero(void* ptr, size_t len) {
    volatile unsigned char* p = ptr;
    while (len--) *p++ = 0;
}

// Example: Clear PIN after use
char pin[64];
// ... use pin ...
xkms_secure_zero(pin, sizeof(pin));
```

### Memory Allocation

- No internal allocations exposed to application
- All buffers freed by module functions
- Two-call pattern prevents buffer overflows

### Session teardown

`C_CloseAllSessions` destroys every session object. `C_Finalize` does the same and then zeroizes every remaining
in-memory object, overwriting each attribute's bytes rather than only dropping the reference. Ciphertext already
persisted to the storage backend is untouched.

## Input Validation

All inputs are validated:

| Input | Validation |
|-------|------------|
| Key IDs | Length limits, character restrictions |
| Key sizes | Allowed values only (2048, 3072, 4096) |
| Curves | Allowed curves only |
| Buffers | NULL checks, size validation |
| Handles | Validity checks |
| ECDH peer public keys | Uncompressed SEC1 form at the curve's required length, and **on-curve**, before any backend sees the point (NIST SP 800-56A Rev. 3 §5.6.2.3.2, invalid-curve attack). Failure is `CKR_MECHANISM_PARAM_INVALID` |
| Authenticated wrap key strength | `C_WrapKeyAuthenticated` refuses a wrapping key shorter than the key it would carry, with `CKR_WRAPPING_KEY_SIZE_RANGE` (NIST SP 800-57 Part 1 §5.6.2). Deliberately not applied to unwrap, nor to plain `C_WrapKey` |

The ECDH check runs inside the module, so it holds identically for the software, TPM, PKCS#11 and cloud KMS
backends.

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
  audit_file: /var/log/goxkms/audit.log
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

### Mandatory TLS for Remote Targets

`Config.Validate` (`pkg/pkcs11/module/config.go`) refuses to start against a remote target with TLS disabled. A
`unix://` target is exempt -- it never leaves the host -- but any `dns://` or `host:port` target with
`tls.enabled: false` fails with `ErrInsecureRemoteTarget` unless `AllowInsecureTransport` is explicitly set. This
matters because PKCS#11 traffic can include raw exported key material, and the gRPC transport falls back to
plaintext (`insecure.NewCredentials()`) whenever TLS is off. `AllowInsecureTransport` exists only for test/dev use
against a loopback or containerized server (`allow_insecure_transport` config key or
`XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` environment variable) and must never be set in production.

A configuration file must not be group- or world-readable (`checkConfigFilePermissions`): `LoadFromFile` refuses
to load a file whose mode has any of the `0077` bits set, because the INI format accepts `so_pin` and `user_pin`
in cleartext. A configuration load or validation failure now fails `C_Initialize` closed -- the module does not
fall back to default values on a bad or unreadable configuration file.

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
sudo mkdir -p /var/run/xkms
sudo chown root:xkms-users /var/run/xkms
sudo chmod 750 /var/run/xkms

# Socket created with restricted permissions
# socket_mode: 0660 in config
```

### Configuration File Permissions

```bash
# Protect configuration files
sudo chown root:xkms /etc/goxkms/pkcs11.yaml
sudo chmod 640 /etc/goxkms/pkcs11.yaml

# Protect TLS keys
sudo chmod 600 /etc/goxkms/*.key
```

## Library Loading Security

### Embedded Mode

The module uses `dlopen()` to load libxkms.so:

```c
// Only load from secure paths
const char* allowed_paths[] = {
    "/usr/lib/libxkms.so",
    "/usr/local/lib/libxkms.so",
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
