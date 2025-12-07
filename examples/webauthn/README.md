# WebAuthn Example

This example demonstrates how to implement passwordless authentication using go-keychain's WebAuthn support.

## Overview

WebAuthn (Web Authentication) enables passwordless login using:
- Hardware security keys (YubiKey, etc.)
- Platform authenticators (Touch ID, Windows Hello, etc.)
- Passkeys (synced across devices)

## Components

This example includes:

1. **Server** (`server/main.go`) - A complete WebAuthn server with REST API endpoints
2. **Client** (`client/`) - HTML/JavaScript client for browser-based authentication

## Prerequisites

- Go 1.21 or later
- A modern web browser with WebAuthn support
- (Optional) A hardware security key for testing

## Running the Example

### 1. Start the Server

```bash
cd examples/webauthn/server
go run main.go
```

The server will start on `https://localhost:8443`.

**Note:** The server uses a self-signed certificate. You'll need to accept the security warning in your browser.

### 2. Open the Client

Open your browser to: `https://localhost:8443`

### 3. Register a Credential

1. Enter your email address
2. Click "Register"
3. Follow your browser's prompts to create a credential
4. Upon success, you'll see a confirmation message

### 4. Authenticate

1. Click "Login"
2. Use your registered credential to authenticate
3. Upon success, you'll see your user information

## Server Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTPS Server (:8443)                     │
├─────────────────────────────────────────────────────────────┤
│                      HTTP Handlers                          │
│  /                    - Serve static files                  │
│  /api/v1/webauthn/registration/begin   - Start registration │
│  /api/v1/webauthn/registration/finish  - Complete reg       │
│  /api/v1/webauthn/registration/status  - Check status       │
│  /api/v1/webauthn/login/begin          - Start login        │
│  /api/v1/webauthn/login/finish         - Complete login     │
├─────────────────────────────────────────────────────────────┤
│                    WebAuthn Service                         │
│  - User management                                          │
│  - Session management                                       │
│  - Credential management                                    │
├─────────────────────────────────────────────────────────────┤
│                    Memory Stores                            │
│  (Replace with database stores for production)              │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Registration

**Begin Registration**
```bash
curl -X POST https://localhost:8443/api/v1/webauthn/registration/begin \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "display_name": "John Doe"}' \
  -k
```

Response includes:
- `X-Session-Id` header for session tracking
- WebAuthn `publicKey` creation options

**Finish Registration**
```bash
curl -X POST https://localhost:8443/api/v1/webauthn/registration/finish \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: <session-id>" \
  -d '<authenticator-response>' \
  -k
```

### Authentication

**Begin Login**
```bash
# With email (for specific user)
curl -X POST https://localhost:8443/api/v1/webauthn/login/begin \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}' \
  -k

# Without email (discoverable credentials)
curl -X POST https://localhost:8443/api/v1/webauthn/login/begin \
  -H "Content-Type: application/json" \
  -d '{}' \
  -k
```

**Finish Login**
```bash
curl -X POST https://localhost:8443/api/v1/webauthn/login/finish \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: <session-id>" \
  -d '<authenticator-assertion>' \
  -k
```

## Configuration

The server can be configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBAUTHN_RP_ID` | `localhost` | Relying Party ID (your domain) |
| `WEBAUTHN_RP_NAME` | `go-keychain Example` | Display name shown to users |
| `WEBAUTHN_RP_ORIGINS` | `https://localhost:8443` | Allowed origins (comma-separated) |
| `PORT` | `8443` | Server port |

## Production Considerations

### 1. Use Persistent Storage

Replace memory stores with database-backed implementations:

```go
// Instead of:
userStore := webauthn.NewMemoryUserStore()

// Use:
userStore := NewDatabaseUserStore(db)
```

### 2. Configure Proper Origins

Set `WEBAUTHN_RP_ORIGINS` to your production domain(s):

```bash
export WEBAUTHN_RP_ORIGINS="https://example.com,https://www.example.com"
```

### 3. Enable Rate Limiting

The server includes rate limiting support:

```go
rateLimiter := ratelimit.NewLimiter(&ratelimit.Config{
    Enabled:        true,
    RequestsPerMin: 60,
    Burst:          10,
})
```

### 4. Use Real TLS Certificates

Replace the self-signed certificate with a proper certificate:

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS13,
}
```

### 5. Session Cleanup

Enable automatic session cleanup:

```go
stores := rest.NewWebAuthnStores(&rest.WebAuthnStoresConfig{
    SessionTTL: 5 * time.Minute,
})
cancel := stores.StartCleanupRoutine(ctx, time.Minute)
defer cancel()
```

## Security Best Practices

1. **HTTPS Required**: WebAuthn only works over HTTPS (except localhost)
2. **Origin Validation**: Always validate origins match your domain
3. **Session Expiration**: Keep session TTL short (2-5 minutes)
4. **Rate Limiting**: Protect against brute force attacks
5. **Credential Backup**: Encourage users to register multiple credentials

## Troubleshooting

### "NotAllowedError: The operation is not allowed"

- Ensure you're using HTTPS
- Check that the origin matches `WEBAUTHN_RP_ORIGINS`
- Verify the RP ID matches your domain

### "InvalidStateError: The authenticator was previously registered"

- The credential is already registered for this user
- Use a different authenticator or delete the existing credential

### "SecurityError: The operation is insecure"

- You're likely on HTTP instead of HTTPS
- localhost is exempt, but requires HTTPS for other domains

## Further Reading

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [go-keychain WebAuthn Documentation](../../docs/usage/webauthn.md)
- [FIDO Alliance](https://fidoalliance.org/)
