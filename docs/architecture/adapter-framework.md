# Authentication Adapter Framework

## Overview

go-xkms provides a pluggable authentication adapter framework that enforces cryptographic authentication for all requests. The system supports JWT Bearer tokens, mutual TLS (mTLS), OpenID Connect (OIDC), and PKCS#11-backed TLS. There are no API keys or passwords — all authentication is based on cryptographic proof.

## Authentication Adapters

### Interface

Located in `pkg/auth/auth.go`, the `Authenticator` interface allows applications to implement custom authentication:

```go
type Authenticator interface {
    // AuthenticateHTTP authenticates an HTTP request
    AuthenticateHTTP(r *http.Request) (*Identity, error)

    // AuthenticateGRPC authenticates a gRPC request
    AuthenticateGRPC(ctx context.Context, md metadata.MD) (*Identity, error)

    // Name returns the authenticator name
    Name() string
}
```

### Identity

The `Identity` struct represents an authenticated user or service:

```go
type Identity struct {
    Subject    string                 // Unique identifier
    Claims     map[string]interface{} // Roles, permissions, etc.
    Attributes map[string]string      // Metadata (auth_method, remote_addr, etc.)
}
```

Helper methods:
- `HasRole(role string) bool` - Check if identity has a specific role
- `HasPermission(permission string) bool` - Check if identity has a permission

### Built-in Authenticators

#### 1. JWTAuthenticator (`pkg/auth/jwt.go`)

Authenticates requests using signed JWT Bearer tokens. Tokens are verified against a configured public key.

```go
config := &auth.JWTConfig{
    PublicKey:  publicKey,         // crypto.PublicKey (required)
    Issuer:    "my-issuer",       // Expected issuer claim (optional)
    Audience:  []string{"xkms"}, // Expected audience claim (optional)
    HeaderName: "Authorization",  // HTTP header (default: "Authorization")
}

authenticator, err := auth.NewJWTAuthenticator(config)
```

Features:
- Bearer token extraction from `Authorization` header
- Public key signature verification (RSA, ECDSA, Ed25519)
- Issuer and audience claim validation
- Subject, role, and username extraction from token claims
- Works across HTTP and gRPC

#### 2. MTLSAuthenticator (`pkg/auth/mtls.go`)

Authenticates using mutual TLS client certificates:

```go
config := &auth.MTLSConfig{
    // Optional: Custom claim extraction from client certificate
    ExtractClaims: func(cert *x509.Certificate) map[string]interface{} {
        return map[string]interface{}{
            "organization": cert.Subject.Organization,
            "roles":        extractRolesFromCert(cert),
        }
    },

    // Optional: Custom subject extraction
    ExtractSubject: func(cert *x509.Certificate) string {
        return cert.Subject.CommonName
    },

    // Optional: Map certificate fingerprints to users
    UserStore: myUserStore,
}

authenticator := auth.NewMTLSAuthenticator(config)
```

Default behavior:
- Subject: Certificate Common Name (fallback to DNS name, then serial number)
- Claims: Organization, OU, Country, Province, Locality, DNS names, email addresses, extended key usage
- When a `UserStore` is configured, the authenticator looks up users by the SHA-256 fingerprint of the client certificate and enriches the identity with user role information

#### 3. OIDCAuthenticator (`pkg/auth/oidc.go`)

Authenticates using OpenID Connect with automatic provider discovery:

```go
config := &auth.OIDCConfig{
    Issuer:       "https://auth.example.com", // OIDC provider URL (required)
    ClientID:     "my-client-id",             // OAuth2 client ID (required)
    Audience:     []string{"xkms"},          // Expected audience (optional)
    JWKSCacheTTL: time.Hour,                 // JWKS cache TTL (default: 1h)
    HTTPClient:   customHTTPClient,           // Custom HTTP client (optional)
}

authenticator, err := auth.NewOIDCAuthenticator(ctx, config)
```

Features:
- Automatic OIDC discovery via `.well-known/openid-configuration`
- JWKS key fetching with configurable cache TTL
- ID token validation with signature verification
- Access token validation via userinfo endpoint fallback
- Role extraction from standard claims (`roles`, `groups`, Keycloak `realm_access`)

#### 4. AdaptiveAuthenticator (`pkg/auth/adaptive.go`)

Automatically switches between open access (bootstrap mode) and required authentication based on whether users exist in the system:

```go
config := &auth.AdaptiveConfig{
    UserChecker:           myUserStore,       // Checks for existing users (required)
    RequiredAuthenticator: jwtAuthenticator,  // Used when users exist (required)
    CacheExpiry:           30 * time.Second,  // User check cache TTL (default: 30s)
    Logger:                slogLogger,        // Optional logger
}

authenticator, err := auth.NewAdaptiveAuthenticator(config)
```

Behavior:
- **Bootstrap mode** (no users): All requests allowed with anonymous identity
- **Secured mode** (users exist): Delegates to the configured required authenticator
- Caches user existence check with configurable TTL
- Logs mode transitions

#### 5. CompositeAuthenticator (`pkg/auth/composite.go`)

Chains multiple authenticators and returns the first successful result:

```go
authenticator, err := auth.NewCompositeAuthenticator(
    mtlsAuthenticator,
    jwtAuthenticator,
    oidcAuthenticator,
)
```

Tries each authenticator in order. Returns the identity from the first one that succeeds. If all fail, returns the error from the last authenticator.

#### 6. NoOpAuthenticator (`pkg/auth/noop.go`)

Allows all requests with an anonymous identity. Intended for:
- Development and testing
- Bootstrap mode (via AdaptiveAuthenticator)
- When authentication is handled externally (reverse proxy, service mesh)

```go
auth := auth.NewNoOpAuthenticator()
```

#### 7. PKCS11TLSConfig (`pkg/auth/pkcs11_tls.go`)

Creates a `tls.Config` backed by a PKCS#11 hardware token for client certificate authentication:

```go
config := &auth.PKCS11TLSConfig{
    ModulePath: "/usr/lib/libxkey11.so", // PKCS#11 shared object
    SlotID:     0,                        // Token slot
    PIN:        tokenPIN,                 // Token PIN
    CertLabel:  "my-cert",               // Certificate label filter (optional)
    CACerts:    caCertPool,              // CA certs for server verification (optional)
}

tlsConfig, cleanup, err := auth.NewPKCS11TLSConfig(config)
defer cleanup()
```

Features:
- Private key operations stay within the hardware token boundary
- Supports RSA (PKCS#1 v1.5, PSS), ECDSA, and Ed25519 signing
- Automatic certificate and matching key discovery via CKA_ID

### Custom Authenticator Example

```go
type MyAuthenticator struct {
    // your auth system
}

func (a *MyAuthenticator) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
    token := r.Header.Get("Authorization")

    // Validate with your auth system
    user, err := a.validateToken(token)
    if err != nil {
        return nil, err
    }

    return &auth.Identity{
        Subject: user.ID,
        Claims: map[string]interface{}{
            "roles": user.Roles,
        },
        Attributes: map[string]string{
            "auth_method": "custom",
        },
    }, nil
}

func (a *MyAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*auth.Identity, error) {
    // Similar implementation for gRPC
}

func (a *MyAuthenticator) Name() string {
    return "my-custom-auth"
}
```

## TLS/mTLS Configuration

TLS/mTLS support is available across all server interfaces:

- REST server TLS/mTLS configuration
- gRPC server TLS/mTLS configuration
- QUIC server TLS/mTLS configuration (requires TLS 1.3)
- MCP server TLS/mTLS configuration

### Features

1. **TLS Configuration** (`pkg/config/tls.go`)
   - Certificate and key loading from files
   - TLS version control (TLS 1.2 - TLS 1.3)
   - Cipher suite configuration
   - Client certificate verification modes (none, request, require, verify, require_and_verify)
   - Multiple CA certificate support
   - Server cipher preference control

2. **Server Support**
   - **REST**: HTTPS with optional client cert verification
   - **gRPC**: TLS with optional mTLS
   - **QUIC**: HTTP/3 with TLS 1.3 (required)
   - **MCP**: TCP with TLS/mTLS

3. **Integration**
   - Unified TLS configuration structure across all servers
   - Automatic mTLS authentication when client certificates are required
   - Identity extraction from client certificates
   - Context propagation of authenticated identity

## Configuration

Authentication is configured via YAML:

```yaml
auth:
  enabled: true
  type: adaptive    # noop, mtls, jwt, adaptive, composite

  # JWT configuration
  jwt:
    issuer: "my-issuer"
    audience: ["xkms"]

  # mTLS uses client certificates from TLS config
  mtls: true

  # Adaptive: auto-switch between noop (bootstrap) and required auth
  adaptive: true

  # Composite: chain multiple auth methods
  composite:
    methods: ["jwt", "mtls"]

  # RBAC
  rbac: true
```

## Examples

### REST Server with JWT Authentication

```go
authenticator, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
    PublicKey: publicKey,
    Issuer:   "my-issuer",
})

server, err := rest.NewServer(&rest.Config{
    Port:          8443,
    Backends:      backends,
    TLSConfig:     tlsConfig,
    Authenticator: authenticator,
})
```

### REST Server with mTLS

```go
// Configure mTLS with client certificate verification
tlsCfg := &config.TLSConfig{
    Enabled:    true,
    CertFile:   "/path/to/server-cert.pem",
    KeyFile:    "/path/to/server-key.pem",
    CAFile:     "/path/to/ca-cert.pem",
    ClientAuth: "require_and_verify",
    MinVersion: "TLS1.2",
}

tlsConfig, err := tlsCfg.LoadTLSConfig()

authenticator := auth.NewMTLSAuthenticator(&auth.MTLSConfig{
    UserStore: myUserStore, // Maps cert fingerprints to users
})

server, err := rest.NewServer(&rest.Config{
    Port:          8443,
    Backends:      backends,
    TLSConfig:     tlsConfig,
    Authenticator: authenticator,
})
```

### Composite Authentication (JWT + mTLS)

```go
jwtAuth, _ := auth.NewJWTAuthenticator(&auth.JWTConfig{
    PublicKey: publicKey,
})

mtlsAuth := auth.NewMTLSAuthenticator(&auth.MTLSConfig{
    UserStore: myUserStore,
})

composite, _ := auth.NewCompositeAuthenticator(mtlsAuth, jwtAuth)

server, err := rest.NewServer(&rest.Config{
    Port:          8443,
    Backends:      backends,
    TLSConfig:     tlsConfig,
    Authenticator: composite,
})
```

### Adaptive Authentication (Bootstrap to Secured)

```go
jwtAuth, _ := auth.NewJWTAuthenticator(&auth.JWTConfig{
    PublicKey: publicKey,
})

adaptive, _ := auth.NewAdaptiveAuthenticator(&auth.AdaptiveConfig{
    UserChecker:           userStore,
    RequiredAuthenticator: jwtAuth,
})

server, err := rest.NewServer(&rest.Config{
    Port:          8443,
    Backends:      backends,
    TLSConfig:     tlsConfig,
    Authenticator: adaptive,
})
```

### Accessing Identity in Handlers

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    identity := auth.GetIdentity(r.Context())

    if identity == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    if !identity.HasRole("admin") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Process request...
}
```

## Best Practices

1. **Authentication**
   - Use mTLS for service-to-service communication
   - Use JWT or OIDC for user-facing authentication
   - Use AdaptiveAuthenticator for smooth bootstrap-to-secured transitions
   - Use CompositeAuthenticator to support multiple auth methods simultaneously
   - Use PKCS#11-backed TLS for hardware-protected client credentials

2. **Security**
   - Always use TLS in production
   - Require mTLS for privileged operations
   - Use short-lived JWT tokens with appropriate audience and issuer claims
   - Monitor authentication failures via audit logging
   - Use hardware tokens (PKCS#11, TPM) for private key protection
