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

`enable_rbac: true` additionally requires `storage.backend: "qrdb"` — see
[RBAC requires the qrdb storage backend](#rbac-requires-the-qrdb-storage-backend).

```yaml
storage:
  backend: "qrdb"   # required by auth.enable_rbac below

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

### RBAC requires the qrdb storage backend

Roles and permissions live in the qrdb identity plane, and that plane exists
only when qrdb is the storage backend. `auth.enable_rbac: true` therefore
requires:

```yaml
storage:
  backend: "qrdb"
```

With any other backend (`pebble`, `file`, `memory`) there is no qrdb client, the
authorizer cannot be built, and every transport authorizes every request. The
daemon refuses to start in that combination: `Config.ComplianceGaps`
(`pkg/config/config.go`) reports it as a posture gap, and startup aborts unless
the operator explicitly opts into development mode with `--insecure` /
`XKMS_INSECURE=true`.

Set `storage.backend: "qrdb"` or disable `auth.enable_rbac`.

### Composite mTLS + JWT

To accept both JWT tokens and mTLS client certificates on the same port:

```yaml
storage:
  backend: "qrdb"   # required by auth.enable_rbac below

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
  # The jwt method needs a verification key; a composite chain that lists
  # "jwt" without auth.jwt.public_key_file fails startup.
  jwt:
    public_key_file: /etc/xkms/jwt-public.pem
    issuer: "https://issuer.example.com"
    audience: ["xkms"]
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
resolution strategies, tried in order (`MTLSAuthenticator.buildIdentity`,
`pkg/auth/mtls.go`):

1. **SPKI thumbprint lookup** -- If a `UserStore` is configured, the canonical
   SPKI thumbprint (SHA-256 over SubjectPublicKeyInfo, base64url) is computed
   with `qrdbsdk.ComputeSPKIThumbprint` and looked up against the user's cert
   bindings. When a match is found and the user is enabled, `Username` becomes
   the identity subject, the user's `TenantID` becomes the identity tenant, and
   the user's `Role` becomes `Identity.Roles`. A matched but disabled user
   yields `ErrUserDisabled`. Binding by public key rather than by certificate
   DER means a re-issued certificate for the same key still resolves.

2. **Certificate field extraction** -- When no thumbprint match exists (or no
   `UserStore` is configured), identity is extracted directly from the X.509
   fields: `Subject.CommonName` becomes the subject (falling back to the first
   DNS SAN, then the serial), the first `Subject.OrganizationalUnit` becomes the
   tenant, and `Subject.Organization`, OU, DNS SANs, email addresses, and
   extended key usages are recorded in `Identity.Metadata`. **No roles are
   assigned on this path**, so with RBAC enabled such an identity holds no
   grants.

The `auth.UserStore` interface bridges the identity store to the
authenticator, translating user records into `auth.MTLSUser` values. The
production implementation is `auth.QRDBUserStore` (`pkg/auth/qrdb_userstore.go`),
which resolves users from the embedded qrdb node by their certificate SPKI
thumbprint — there is no local xkms user package.

### Certificate Binding

Create the user and bind its client certificate in one step, so the thumbprint
lookup succeeds:

```bash
xkmsctl admin create alice \
  --method mtls \
  --cert-file /tmp/alice.pem \
  --display-name "Alice"
```

This creates the user with the `admin` role and stores a cert binding holding
the certificate's SPKI thumbprint and `NotAfter`. A PKCS#11 token can be used
instead of a PEM file with `--pkcs11-module`.

### RBAC Role Model

Role definitions and grants live in the qrdb identity plane, not in xkms. The
canonical names are qrdb's FIPS 140-3 six-role model, mirrored by
`cmd/xkmsctl/roles.go` so the strings the CLI sends match what the server
understands. Each user has exactly one role.

| Role | Intent |
|------|--------|
| `so` | Security Officer: module initialization and PIN management |
| `admin` | Full access to manage xkms and its users |
| `operator` | Manage keys and certificates, not users |
| `user` | Use keys for cryptographic operations, not manage them |
| `auditor` | View audit logs and key metadata only |
| `custodian` | Participate in key ceremonies and manage key shares |

The user's role is resolved from the embedded qrdb identity store via
`auth.QRDBUserStore`; the permission check for the role is then made by qrdb
itself through `auth.Authorizer` (`pkg/auth/authorize.go`). Inspect or change
grants with `xkms.Auth(qrdbClient).Roles()` / `.Permissions()` / `.RBAC()`.
See [RBAC](../architecture/rbac.md) for the resource:action vocabulary.

### Transport Enforcement

Every transport authorizes through the same qrdb-backed `auth.Authorizer`, so a
role grant means the same thing regardless of how the request arrives.

| Transport | Gate | RBAC disabled (`enable_rbac: false`) |
|-----------|------|--------------------------------------|
| REST | `RBACMiddleware.RequirePermission` per route | Routes registered without the decorator — no check |
| gRPC | `Service.authorize(ctx, resource, action, id)` | Disabled `Authorizer` allows all |
| QUIC | `Server.authorize(w, r, resource, action)` | Disabled `Authorizer` allows all |
| MCP | `Server.authorizeMethod(ctx, method)` before dispatch | Gate is a no-op — no check |

Authentication is mandatory on every transport whether or not RBAC is enabled.

MCP maps each JSON-RPC method to the resource:action pair the equivalent
REST/gRPC/QUIC operation already requires (`pkg/api/mcp/authz.go`); the gate
runs in `handleRequest` before any dispatch path, so the method table, the
connection-bound `xkms.subscribe`, and the build-tagged `frost.*` namespace are
all covered. Only `health` is public. Denials are reported as JSON-RPC errors
in the implementation-defined range: `-32002` for a missing identity (the
REST/QUIC 401) and `-32003` for a missing grant (403). A dispatchable method
with no permission mapping is denied, so the surface fails closed.

Enabling RBAC without a usable authorizer is refused at construction
(`mcp: authorizer is required when rbac is enabled`): xkmsd logs the failure
and does not start the MCP listener rather than serving an unauthorized surface
that operators believe is protected.

### Certificate-Only Identity (No UserStore)

Without a `UserStore` — or when the certificate's SPKI thumbprint is not bound
to any user — the authenticator produces a certificate-only identity. It carries
the certificate's fields in `Identity.Metadata` (including
`organizational_unit`) and takes its tenant from the first OU, but **it carries
no roles**. There is no OU-to-role convention in the code.

With RBAC enabled such an identity holds no grants and is denied by every
transport gate. Bind the certificate to a user (see
[Certificate Binding](#certificate-binding)) so a role is resolved.

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
  +---> UserStore lookup by SPKI thumbprint
  |       |
  |       +-- Found + Enabled --> Identity{Subject: username,
  |       |                                TenantID: user tenant,
  |       |                                Roles: [role]}
  |       +-- Found + Disabled -> ErrUserDisabled
  |       +-- Not found --------+
  |                              |
  +---> Identity from cert fields: CN, OU (tenant), O, SANs -- no roles
  |
  v
auth.Authorizer.Authorize(ctx, identity, resource, action)
  -> qrdbClient.RBAC().Authorize(...)
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

- The `MTLSAuthenticator` returns this error when the certificate's SPKI
  thumbprint matches a user whose `Enabled` field is `false`.
- Re-enable the account: `xkmsctl admin enable alice`.

### RBAC Enabled but Every Request Is Allowed

**Symptom**: `enable_rbac: true`, yet callers with no grants succeed; the log
shows `RBAC enabled but no qrdb identity plane; authorization is permissive`.

- The storage backend is not `qrdb`, so the authorizer could not be built. Set
  `storage.backend: "qrdb"`.
- This state is only reachable when the daemon was started with `--insecure` /
  `XKMS_INSECURE=true`; a normal start refuses the combination. See
  [RBAC requires the qrdb storage backend](#rbac-requires-the-qrdb-storage-backend).

See [RBAC](../architecture/rbac.md) for the role model and permission details.
