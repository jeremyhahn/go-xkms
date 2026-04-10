# Authentication

## Supported Methods

| Method | Authenticator | Use Case |
|--------|---------------|----------|
| mTLS | `MTLSAuthenticator` | Service accounts, hardware-bound identity via PKCS#11 tokens |
| JWT | `JWTAuthenticator` | API clients, post-WebAuthn session tokens |
| OIDC | `OIDCAuthenticator` | Enterprise SSO (Keycloak, Okta, Azure AD) |
| FIDO2/WebAuthn | WebAuthn + JWT issuance | Interactive human authentication |
| Composite | `CompositeAuthenticator` | Chain multiple methods (first success wins) |
| Adaptive | `AdaptiveAuthenticator` | Bootstrap-to-production transition |

## PKCS#11 Client Authentication

Hardware tokens (YubiKey, SmartCard, HSM) can provide mTLS client certificates
for CLI authentication. `NewPKCS11TLSConfig` opens a PKCS#11 session, locates
the certificate and matching private key by `CKA_ID`, and constructs a
`tls.Config` with a `crypto.Signer` backed by the token. Private key material
never leaves the hardware boundary.

### CLI Flags

| Flag | Description |
|------|-------------|
| `--pkcs11-module` | Path to the PKCS#11 `.so` shared library |
| `--pkcs11-slot` | Slot ID on the token (default: 0) |
| `--pkcs11-pin` | PIN for the token |

### Example

```bash
xkmsctl --protocol grpc \
  --server grpcs://xkms.example.com:9443 \
  --pkcs11-module /usr/lib/libxkey11.so \
  --pkcs11-pin 123456 \
  key list
```

## File-based mTLS

Use PEM files for client certificate authentication when hardware tokens are
not available.

| Flag | Description |
|------|-------------|
| `--tls-cert` | Path to client certificate PEM file |
| `--tls-key` | Path to client private key PEM file |
| `--tls-ca` | Path to CA certificate for server verification |

```bash
xkmsctl --protocol grpc \
  --server grpcs://xkms.example.com:9443 \
  --tls-cert /path/to/client.pem \
  --tls-key /path/to/client-key.pem \
  --tls-ca /path/to/ca.pem \
  key list
```

## Composite Authentication

`CompositeAuthenticator` chains multiple authenticators and returns the first
successful result. If all fail, the error from the last authenticator is
returned. This allows endpoints to accept either JWT tokens or mTLS client
certificates on the same port.

## Server-Side mTLS Configuration

The server requires both the `tls` and `auth` sections to be configured for
mTLS. The `tls` section controls the TLS handshake (certificate verification
policy), while the `auth` section controls identity extraction and RBAC
enforcement.

```yaml
tls:
  enabled: true
  cert_file: /etc/xkms/tls/server.pem
  key_file: /etc/xkms/tls/server-key.pem
  ca_file: /etc/xkms/tls/ca.pem

  # Require and verify client certificates
  client_auth: require_and_verify
  client_cas:
    - /etc/xkms/tls/ca.pem
    - /etc/xkms/tls/intermediate-ca.pem

  # TLS hardening
  min_version: TLS1.2
  prefer_server_ciphers: true
  watch_cert_files: true

auth:
  enabled: true
  type: mtls              # noop, jwt, mtls, adaptive, composite
  mtls: true
  enable_rbac: true
```

### `client_auth` Values

| Value | Behavior |
|-------|----------|
| `none` | No client certificate requested |
| `request` | Client certificate requested but not required |
| `require` | Client certificate required but not verified |
| `verify` | Client certificate verified if provided |
| `require_and_verify` | Client certificate required and verified against `client_cas` |

For production mTLS, use `require_and_verify`. The `client_cas` list must
include every CA that signs client certificates.

### Composite mTLS + JWT

To accept both JWT tokens and mTLS client certificates on the same port:

```yaml
tls:
  enabled: true
  cert_file: /etc/xkms/tls/server.pem
  key_file: /etc/xkms/tls/server-key.pem
  ca_file: /etc/xkms/tls/ca.pem
  client_auth: verify       # verify if provided, don't require
  client_cas:
    - /etc/xkms/tls/ca.pem

auth:
  enabled: true
  type: composite
  mtls: true
  enable_rbac: true
  composite:
    methods:
      - jwt
      - mtls
```

Use `client_auth: verify` (not `require_and_verify`) so JWT-only clients
can connect without a client certificate.

## Certificate Workflow

### 1. Generate a CA Certificate

```bash
xkmsctl key create \
  --backend software \
  --algorithm ecdsa \
  --curve P-384 \
  --id ca-root

xkmsctl cert create \
  --key-id ca-root \
  --cn "xKMS Root CA" \
  --is-ca \
  --max-path-len 1 \
  --valid-for 87600h
```

### 2. Issue a Server Certificate

```bash
xkmsctl key create \
  --backend software \
  --algorithm ecdsa \
  --curve P-256 \
  --id server-tls

xkmsctl cert create \
  --key-id server-tls \
  --cn "xkms.example.com" \
  --san-dns xkms.example.com \
  --san-ip 10.0.0.1 \
  --issuer-key-id ca-root \
  --valid-for 8760h
```

### 3. Issue a Client Certificate

```bash
xkmsctl key create \
  --backend software \
  --algorithm ecdsa \
  --curve P-256 \
  --id alice-client

xkmsctl cert create \
  --key-id alice-client \
  --cn "alice" \
  --ou "operators" \
  --issuer-key-id ca-root \
  --extended-key-usage client_auth \
  --valid-for 8760h
```

### 4. Export Certificates

```bash
xkmsctl cert export --key-id ca-root     > /etc/xkms/tls/ca.pem
xkmsctl cert export --key-id server-tls  > /etc/xkms/tls/server.pem
xkmsctl key export  --id server-tls      > /etc/xkms/tls/server-key.pem
xkmsctl cert export --key-id alice-client > /tmp/alice.pem
xkmsctl key export  --id alice-client     > /tmp/alice-key.pem
```

### 5. Connect with the Client Certificate

```bash
xkmsctl --protocol grpc \
  --server grpcs://xkms.example.com:9443 \
  --tls-cert /tmp/alice.pem \
  --tls-key /tmp/alice-key.pem \
  --tls-ca /etc/xkms/tls/ca.pem \
  key list
```

## mTLS + RBAC Integration

When mTLS is enabled with RBAC (`enable_rbac: true`), the `MTLSAuthenticator`
extracts identity from the client certificate and maps it to RBAC roles.

### Identity Extraction

The authenticator builds an `Identity` from the client certificate with two
resolution strategies, tried in order:

1. **Certificate fingerprint lookup** -- If a `UserStore` is configured, the
   SHA-256 fingerprint of the client certificate's DER bytes is computed via
   `ComputeCertFingerprint` and looked up against user `CertBindings`. When a
   match is found, the user's `Username` becomes the identity subject and the
   user's `Role` is injected into claims.

2. **Certificate field extraction** -- When no fingerprint match exists (or no
   `UserStore` is configured), identity is extracted directly from the X.509
   subject fields:
   - `Subject.CommonName` becomes the identity subject
   - `Subject.Organization`, `Subject.OrganizationalUnit`, DNS SANs, and email
     addresses are added as claims

The `MTLSUserStoreAdapter` (`pkg/user/mtls_adapter.go`) bridges the user store
to the authenticator, translating `user.User` records into `auth.MTLSUser`
values.

### Certificate Binding

Bind a client certificate to a user account so the fingerprint lookup succeeds:

```bash
xkmsctl admin user bind-cert \
  --username alice \
  --cert /tmp/alice.pem \
  --name "alice workstation"
```

This stores a `CertBinding` containing the SHA-256 fingerprint, subject DN,
issuer DN, serial, and expiry on the user record.

### RBAC Role Model

Roles follow FIPS 140-2 separation of duties. Each user has exactly one role.

| Role | Permissions |
|------|-------------|
| `admin` | `*:*` -- full access to all resources |
| `operator` | `keys:*`, `certificates:*`, `secrets:create/read/update/delete` |
| `auditor` | `audit:read/list`, `keys:list`, `certificates:list`, `users:list` |
| `user` | `keys:sign/verify/encrypt/decrypt`, `secrets:read` |

The `UserRBACAdapter` (`pkg/user/rbac.go`) resolves the user's role from the
store and checks permissions against the role definitions in `MemoryRBACAdapter`.

### Claim-to-Role Mapping (No UserStore)

When operating without a `UserStore`, the authenticator extracts the
`organizational_unit` claim from the certificate's OU field. The server
application is responsible for mapping OU values to RBAC roles. A typical
convention:

| Certificate OU | Mapped Role |
|---------------|-------------|
| `admins` | `admin` |
| `operators` | `operator` |
| `auditors` | `auditor` |
| (default) | `user` |

### Authentication Flow

```
Client TLS Handshake
  |
  v
Server verifies cert chain (client_auth: require_and_verify)
  |
  v
MTLSAuthenticator.AuthenticateHTTP / AuthenticateGRPC
  |
  +---> UserStore lookup by SHA-256 fingerprint
  |       |
  |       +-- Found + Enabled --> Identity{Subject: username, Claims: {roles: [role]}}
  |       +-- Found + Disabled -> ErrUserDisabled
  |       +-- Not found --------+
  |                              |
  +---> Extract from cert fields: CN, OU, O, SANs
  |
  v
RBAC CheckPermission(subject, resource:action)
  |
  v
Allow / Deny
```

## Troubleshooting

### Certificate Chain Validation Failures

**Symptom**: `tls: failed to verify certificate` or `x509: certificate signed
by unknown authority`.

- Verify the server's `client_cas` includes the CA that signed the client
  certificate. For intermediate CAs, include the full chain.
- Confirm the client's `--tls-ca` includes the CA that signed the server
  certificate.
- Check that the certificate's Basic Constraints and Key Usage extensions are
  correct (CA certificates need `IsCA: true`; client certificates need
  `ExtKeyUsageClientAuth`).

```bash
openssl verify -CAfile ca.pem client.pem
openssl x509 -in client.pem -noout -text | grep -A2 "Key Usage"
```

### Expired Certificates

**Symptom**: `x509: certificate has expired or is not yet valid`.

- Check validity with `openssl x509 -in cert.pem -noout -dates`.
- Reissue the certificate using `xkmsctl cert create` with a new
  `--valid-for` duration.
- When `watch_cert_files: true` is set, the server automatically reloads
  certificates on disk change without restart.

### PKCS#11 Token Issues with mTLS

**Symptom**: `pkcs11: no certificate found` or `pkcs11: login failed`.

| Error | Cause | Fix |
|-------|-------|-----|
| `ErrPKCS11ModulePathRequired` | Empty `--pkcs11-module` | Provide the `.so` path |
| `ErrPKCS11PINRequired` | Empty `--pkcs11-pin` | Provide the token PIN |
| `ErrPKCS11NoCertFound` | No X.509 certificate on the token | Import a certificate to the token |
| `ErrPKCS11NoKeyFound` | No private key matching the certificate's `CKA_ID` | Ensure cert and key share the same `CKA_ID` |
| `ErrPKCS11Login` | Wrong PIN or locked token | Verify PIN; check token lockout status |

Verify token contents:

```bash
pkcs11-tool --module /usr/lib/libxkey11.so --list-objects --type cert
pkcs11-tool --module /usr/lib/libxkey11.so --list-objects --type privkey
```

### Clock Skew Problems

**Symptom**: Certificates rejected as "not yet valid" on one host but accepted
on another.

- TLS certificate validation is sensitive to system clock accuracy. A clock
  skew of more than a few minutes can cause `NotBefore` / `NotAfter` checks
  to fail.
- Ensure NTP is running on all nodes: `timedatectl status`.
- For short-lived certificates (hours), keep clock drift under 30 seconds.

### Disabled User Account

**Symptom**: `user account is disabled` (`ErrUserDisabled`).

- The `MTLSAuthenticator` returns this error when the certificate fingerprint
  matches a user whose `Enabled` field is `false`.
- Re-enable the account: `xkmsctl admin user enable --username alice`.

See the [RBAC role model](./README.md) for permission details.
