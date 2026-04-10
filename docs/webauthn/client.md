# Headless WebAuthn Client

The `pkg/webauthn/client` package provides a headless WebAuthn client that acts as the "browser" in the WebAuthn protocol. It bridges a relying party (RP) server and a local authenticator, performing full registration and authentication ceremonies programmatically.

## Architecture

```
  RP Server (go-xkms)          Headless Client           Authenticator
       |                            |                         |
       |  POST registration/begin   |                         |
       |<---------------------------|                         |
       |  CreationOptions           |                         |
       |--------------------------->|                         |
       |                            |  MakeCredential()       |
       |                            |------------------------>|
       |                            |  AttestationResponse    |
       |                            |<------------------------|
       |  POST registration/finish  |                         |
       |<---------------------------|                         |
       |  { user_id, token }        |                         |
       |--------------------------->|                         |
```

## Client API

| Method | Description |
|--------|-------------|
| `NewClient(config)` | Creates client with authenticator adapter |
| `Register(ctx, req)` | Full registration ceremony (begin, CTAP, finish) |
| `Login(ctx, req)` | Full authentication ceremony (begin, CTAP, finish) |
| `Available(ctx)` | Checks both server and authenticator reachability |

## AuthenticatorAdapter Interface

| Method | Description |
|--------|-------------|
| `MakeCredential(options)` | Creates credential from JSON CreationOptions, returns JSON attestation |
| `GetAssertion(options)` | Gets assertion from JSON RequestOptions, returns JSON assertion |
| `Available()` | Reports if authenticator is ready |

## SoftwareAdapter

`SoftwareAdapter` provides an in-memory authenticator for testing:

- Generates ephemeral ECDSA P-256 key pairs
- Produces `"none"` attestation format
- Maintains sign counter per credential
- Thread-safe credential storage

```go
adapter := client.NewSoftwareAdapter()
c, _ := client.NewClient(&client.Config{
    ServerURL:            "https://xkms.example.com:8443",
    AuthenticatorAdapter: adapter,
})
```

## Registration Flow

```go
result, err := c.Register(ctx, &client.RegistrationRequest{
    Username:    "alice@example.com",
    DisplayName: "Alice",
    AuthToken:   setupToken, // optional JWT or bootstrap token
})
// result.UserID, result.JWT
```

## Authentication Flow

```go
result, err := c.Login(ctx, &client.AuthenticationRequest{
    Username:  "alice@example.com",
    AuthToken: existingJWT, // optional
})
// result.UserID, result.JWT
```

## HTTP Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-Session-Id` | Server -> Client -> Server | Session correlation between begin/finish |
| `X-User-Id` | Server -> Client -> Server | User correlation during login |
| `Authorization` | Client -> Server | `Bearer <token>` for authenticated requests |

## Configuration

```go
type Config struct {
    ServerURL            string               // RP server base URL (required)
    HTTPClient           *http.Client         // custom HTTP client (optional)
    TLSConfig            *tls.Config          // TLS config when HTTPClient is nil
    Timeout              time.Duration        // default: 30s
    AuthenticatorAdapter AuthenticatorAdapter  // CTAP2 bridge (required)
}
```

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrServerURLRequired` | Empty server URL |
| `ErrUsernameRequired` | Empty username |
| `ErrRegistrationFailed` | Registration ceremony failed |
| `ErrAuthenticationFailed` | Authentication ceremony failed |
| `ErrServerUnavailable` | Server unreachable |
| `ErrAuthenticatorNotFound` | Authenticator not available |
| `ErrCTAPOperationFailed` | MakeCredential or GetAssertion failed |
| `ErrInvalidServerResponse` | Unexpected response format |
| `ErrInvalidChallenge` | Bad challenge from server |

## Cross-References

- [WebAuthn Server Documentation](../usage/webauthn.md) -- server-side WebAuthn setup
- [FIDO2 Documentation](../fido2/README.md) -- FIDO2/CTAP2 protocol details
