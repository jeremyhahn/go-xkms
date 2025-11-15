# Authentication and Logging Adapter Framework

## Overview

The go-keychain library provides pluggable authentication and logging adapters, allowing applications to integrate their own authentication and logging systems seamlessly.

## Authentication Adapters

### Interface

Located in `pkg/adapters/auth/auth.go`, the `Authenticator` interface allows applications to implement custom authentication:

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
    Attributes map[string]string      // Metadata
}
```

Helper methods:
- `HasRole(role string) bool` - Check if identity has a specific role
- `HasPermission(permission string) bool` - Check if identity has a permission

### Built-in Authenticators

#### 1. NoOpAuthenticator (`pkg/adapters/auth/noop.go`)

Allows all requests with an anonymous identity. Useful for:
- Development/testing
- When authentication is handled externally (reverse proxy, API gateway)

```go
auth := auth.NewNoOpAuthenticator()
```

#### 2. APIKeyAuthenticator (`pkg/adapters/auth/apikey.go`)

Authenticates using API keys via:
- HTTP header (default: `X-API-Key`)
- Query parameter (default: `api_key`)
- Authorization header with Bearer scheme

```go
config := &auth.APIKeyConfig{
    Keys: map[string]*auth.Identity{
        "secret-key-123": {
            Subject: "service-a",
            Claims: map[string]interface{}{
                "roles": []string{"admin"},
            },
        },
    },
    HeaderName: "X-API-Key",  // Optional, defaults to X-API-Key
    QueryParam: "api_key",     // Optional, defaults to api_key
}

authenticator := auth.NewAPIKeyAuthenticator(config)

// Add keys dynamically
authenticator.AddKey("another-key", identity)
authenticator.RemoveKey("old-key")
```

#### 3. MTLSAuthenticator (`pkg/adapters/auth/mtls.go`)

Authenticates using mutual TLS (client certificates):

```go
config := &auth.MTLSConfig{
    // Optional: Custom claim extraction
    ExtractClaims: func(cert *x509.Certificate) map[string]interface{} {
        return map[string]interface{}{
            "organization": cert.Subject.Organization,
            "roles": extractRolesFromCert(cert),
        }
    },

    // Optional: Custom subject extraction
    ExtractSubject: func(cert *x509.Certificate) string {
        return cert.Subject.CommonName
    },
}

authenticator := auth.NewMTLSAuthenticator(config)
```

Default behavior:
- Subject: Certificate Common Name
- Claims: Organization, OU, DNS names, email addresses, extended key usage

### Custom Authenticator Example

```go
type MyAuthenticator struct {
    // your auth system
}

func (a *MyAuthenticator) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
    // Extract token from request
    token := r.Header.Get("Authorization")

    // Validate with your auth system
    user, err := a.validateToken(token)
    if err != nil {
        return nil, err
    }

    return &auth.Identity{
        Subject: user.ID,
        Claims: map[string]interface{}{
            "email": user.Email,
            "roles": user.Roles,
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

## Logging Adapters

### Interface

Located in `pkg/adapters/logger/logger.go`, the `Logger` interface allows applications to integrate their logging system:

```go
type Logger interface {
    Debug(msg string, fields ...Field)
    Info(msg string, fields ...Field)
    Warn(msg string, fields ...Field)
    Error(msg string, fields ...Field)
    Fatal(msg string, fields ...Field)

    With(fields ...Field) Logger
    WithError(err error) Logger
}
```

### Structured Logging

The framework uses structured logging with typed fields:

```go
logger.Info("User authenticated",
    logger.String("user_id", "123"),
    logger.Int("session_duration", 3600),
    logger.Bool("mfa_enabled", true),
)
```

Available field types:
- `String(key, value string)`
- `Int(key string, value int)`
- `Int64(key string, value int64)`
- `Float64(key string, value float64)`
- `Bool(key string, value bool)`
- `Error(err error)`
- `Any(key string, value interface{})`
- `Strings(key string, values []string)`
- `Ints(key string, values []int)`

### Built-in Adapters

#### 1. Standard Library Logger (`pkg/adapters/logger/stdlib.go`)

Wraps Go's standard `log` package:

```go
config := &logger.SlogAdapterConfig{
    Level: logger.LevelInfo,
    Prefix: "[keychain]",
}

log := logger.NewSlogAdapter(config)
```

#### 2. Slog Adapter (`pkg/adapters/logger/slog.go`)

Wraps the slog logger (used internally by go-keychain):

```go
slogLogger := slog.New(os.Stdout).With().Timestamp().Logger()
log := logger.NewSlogAdapter(slogLogger)
```

### Custom Logger Example

```go
type MyLogger struct {
    // your logging system
}

func (l *MyLogger) Info(msg string, fields ...logger.Field) {
    // Convert fields to your format
    myFields := make(map[string]interface{})
    for _, f := range fields {
        myFields[f.Key] = f.Value
    }

    // Log using your system
    l.logger.Info(msg, myFields)
}

// Implement other methods...
```

## Usage with Servers

### Configuring Authentication

```go
// Create authenticator
authenticator := auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
    Keys: loadAPIKeys(),
})

// Configure server (example for REST)
restConfig := &rest.Config{
    Addr:          ":8443",
    Authenticator: authenticator, // Plug in your authenticator
}

server := rest.NewServer(restConfig)
```

### Configuring Logging

```go
// Create logger
log := logger.NewSlogAdapter(mySlogLogger)

// Configure server
serverConfig := &server.Config{
    Logger: log, // Plug in your logger
}
```

### Accessing Identity in Handlers

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    // Get authenticated identity from context
    identity := auth.GetIdentity(r.Context())

    if identity == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Check permissions
    if !identity.HasRole("admin") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // Process request...
}
```

## TLS/mTLS Configuration

### Status

Complete - TLS/mTLS support is available across all server interfaces:

- Authentication adapter framework complete
- mTLS authenticator ready
- REST server TLS/mTLS configuration
- gRPC server TLS/mTLS configuration
- QUIC server TLS/mTLS configuration (requires TLS 1.3)
- MCP server TLS/mTLS configuration

### Features

1. **TLS Configuration** (`internal/config/tls.go`)
   - Certificate and key loading from files
   - TLS version control (TLS 1.0 - TLS 1.3)
   - Cipher suite configuration
   - Client certificate verification modes (none, request, require, verify, require_and_verify)
   - Multiple CA certificate support
   - Server cipher preference control

2. **Server Support**
   - **REST**: HTTPS with optional client cert verification via `rest.Config.TLSConfig`
   - **gRPC**: TLS with optional mTLS via `grpc.ServerConfig.TLSConfig`
   - **QUIC**: HTTP/3 with TLS 1.3 (required) via `quic.Config.TLSConfig`
   - **MCP**: TCP with TLS/mTLS via `mcp.Config.TLSConfig`

3. **Integration**
   - Unified TLS configuration structure across all servers
   - Automatic mTLS authentication when client certificates are required
   - Identity extraction from client certificates
   - Context propagation of authenticated identity

## Examples

### TLS/mTLS Configuration Examples

#### 1. REST Server with TLS and API Key Authentication

```go
package main

import (
    "crypto/tls"

    "github.com/jeremyhahn/go-keychain/internal/config"
    "github.com/jeremyhahn/go-keychain/internal/rest"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
)

func main() {
    // Setup logging
    log := logger.NewSlogAdapter(&logger.SlogAdapterConfig{
        Level: logger.LevelInfo,
    })

    // Load TLS configuration
    tlsCfg := &config.TLSConfig{
        Enabled:  true,
        CertFile: "/path/to/server-cert.pem",
        KeyFile:  "/path/to/server-key.pem",
        MinVersion: "TLS1.2",
        CipherSuites: []string{
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        },
    }

    tlsConfig, err := tlsCfg.LoadTLSConfig()
    if err != nil {
        log.Fatal("Failed to load TLS config", logger.Error(err))
    }

    // Setup API key authentication
    authenticator := auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
        Keys: map[string]*auth.Identity{
            "prod-key-1": {
                Subject: "production-service",
                Claims: map[string]interface{}{
                    "roles": []string{"admin"},
                },
            },
        },
    })

    // Create HTTPS server
    server, err := rest.NewServer(&rest.Config{
        Port:          8443,
        Backends:      backends, // your keystore backends
        TLSConfig:     tlsConfig,
        Authenticator: authenticator,
        Logger:        log,
    })

    if err != nil {
        log.Fatal("Failed to create server", logger.Error(err))
    }

    log.Info("Starting HTTPS server", logger.Int("port", 8443))
    server.Start()
}
```

#### 2. REST Server with mTLS (Client Certificate Authentication)

```go
// Configure mTLS with client certificate verification
tlsCfg := &config.TLSConfig{
    Enabled:    true,
    CertFile:   "/path/to/server-cert.pem",
    KeyFile:    "/path/to/server-key.pem",
    CAFile:     "/path/to/ca-cert.pem",
    ClientAuth: "require_and_verify", // Require and verify client certificates
    MinVersion: "TLS1.2",
}

tlsConfig, err := tlsCfg.LoadTLSConfig()
if err != nil {
    log.Fatal("Failed to load TLS config", logger.Error(err))
}

// Use mTLS authenticator to extract identity from client certificates
authenticator := auth.NewMTLSAuthenticator(&auth.MTLSConfig{
    // Custom claim extraction (optional)
    ExtractClaims: func(cert *x509.Certificate) map[string]interface{} {
        return map[string]interface{}{
            "organization": cert.Subject.Organization,
            "ou":          cert.Subject.OrganizationalUnit,
        }
    },
})

server, err := rest.NewServer(&rest.Config{
    Port:          8443,
    Backends:      backends,
    TLSConfig:     tlsConfig,
    Authenticator: authenticator,
    Logger:        log,
})
```

#### 3. gRPC Server with TLS

```go
import (
    grpcServer "github.com/jeremyhahn/go-keychain/internal/grpc"
)

// Load TLS configuration
tlsCfg := &config.TLSConfig{
    Enabled:  true,
    CertFile: "/path/to/server-cert.pem",
    KeyFile:  "/path/to/server-key.pem",
    MinVersion: "TLS1.2",
}

tlsConfig, err := tlsCfg.LoadTLSConfig()
if err != nil {
    log.Fatal("Failed to load TLS config", logger.Error(err))
}

// Create gRPC server with TLS
server, err := grpcServer.NewServer(&grpcServer.ServerConfig{
    Port:           9090,
    Manager:        backendManager,
    TLSConfig:      tlsConfig,
    Authenticator:  authenticator,
    Logger:         log,
    EnableLogging:  true,
    EnableRecovery: true,
})
```

#### 4. QUIC Server with TLS 1.3 (Required)

```go
import (
    "github.com/jeremyhahn/go-keychain/internal/quic"
)

// QUIC requires TLS 1.3
tlsCfg := &config.TLSConfig{
    Enabled:    true,
    CertFile:   "/path/to/server-cert.pem",
    KeyFile:    "/path/to/server-key.pem",
    MinVersion: "TLS1.3",
}

tlsConfig, err := tlsCfg.LoadTLSConfig()
if err != nil {
    log.Fatal("Failed to load TLS config", logger.Error(err))
}

// Ensure NextProtos includes "h3" for HTTP/3
tlsConfig.NextProtos = []string{"h3"}

server, err := quic.NewServer(&quic.Config{
    Addr:          "localhost:8444",
    KeyStore:      keystore,
    TLSConfig:     tlsConfig,
    Authenticator: authenticator,
    Logger:        log,
})
```

#### 5. MCP Server with mTLS

```go
import (
    "github.com/jeremyhahn/go-keychain/internal/mcp"
)

// Configure mTLS
tlsCfg := &config.TLSConfig{
    Enabled:    true,
    CertFile:   "/path/to/server-cert.pem",
    KeyFile:    "/path/to/server-key.pem",
    CAFile:     "/path/to/ca-cert.pem",
    ClientAuth: "require_and_verify",
    MinVersion: "TLS1.2",
}

tlsConfig, err := tlsCfg.LoadTLSConfig()
if err != nil {
    log.Fatal("Failed to load TLS config", logger.Error(err))
}

// MCP server automatically extracts identity from client certificates when mTLS is enabled
server, err := mcp.NewServer(&mcp.Config{
    Addr:          ":9000",
    KeyStore:      keystore,
    TLSConfig:     tlsConfig,
    Authenticator: authenticator, // Can be NoOp when using mTLS for authentication
    Logger:        log,
})
```

### Complete Authentication Setup (Without TLS)

```go
package main

import (
    "github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
    "github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
    "github.com/jeremyhahn/go-keychain/internal/rest"
)

func main() {
    // Setup logging
    log := logger.NewSlogAdapter(&logger.SlogAdapterConfig{
        Level: logger.LevelInfo,
    })

    // Setup authentication
    authenticator := auth.NewAPIKeyAuthenticator(&auth.APIKeyConfig{
        Keys: map[string]*auth.Identity{
            "prod-key-1": {
                Subject: "production-service",
                Claims: map[string]interface{}{
                    "roles": []string{"read", "write"},
                },
            },
        },
    })

    // Create server (plain HTTP)
    server, err := rest.NewServer(&rest.Config{
        Port:          8080,
        Backends:      backends,
        Authenticator: authenticator,
        Logger:        log,
    })

    if err != nil {
        log.Fatal("Failed to create server", logger.Error(err))
    }

    log.Info("Starting HTTP server", logger.Int("port", 8080))
    server.Start()
}
```

## Best Practices

1. **Authentication**
   - Always validate identities before processing requests
   - Use role-based or permission-based access control
   - Log authentication failures for security monitoring
   - Rotate API keys regularly
   - Use mTLS for service-to-service communication

2. **Logging**
   - Use structured logging with fields instead of string formatting
   - Include request IDs for tracing
   - Log authentication events (success/failure)
   - Avoid logging sensitive data (credentials, PII)
   - Use appropriate log levels

3. **Security**
   - Always use TLS in production
   - Require mTLS for privileged operations
   - Implement rate limiting on authentication endpoints
   - Monitor for suspicious authentication patterns
   - Use short-lived credentials when possible

## Migration Guide

### From Direct Slog Usage

Before:
```go
logger.Info().Str("key", "value").Msg("message")
```

After:
```go
logger.Info("message", logger.String("key", "value"))
```

### Adding Authentication to Existing Code

1. Create authenticator
2. Add to server configuration
3. Update handlers to check identity
4. Test with authenticated and unauthenticated requests

### Testing

Mock authenticators and loggers for testing:

```go
type MockAuthenticator struct{}

func (a *MockAuthenticator) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
    return &auth.Identity{Subject: "test-user"}, nil
}

func (a *MockAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*auth.Identity, error) {
    return &auth.Identity{Subject: "test-user"}, nil
}

func (a *MockAuthenticator) Name() string {
    return "mock"
}
```

