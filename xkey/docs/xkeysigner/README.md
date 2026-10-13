# xkeysigner: crypto.Signer via IPC

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the root module's `pkg/xkeysigner` package; for PIV itself the [piv feature folder](../piv/architecture.md) is normative.

The `pkg/xkeysigner` package implements Go's `crypto.Signer` interface by delegating signing operations to the running xkey over its IPC Unix domain socket. This enables TLS client certificate authentication backed by hardware-protected PIV keys without importing xkey packages (no import cycle).

## Architecture

```
  Application (go-xkms server, CLI, etc.)
       |
  crypto.Signer (xkeysigner.Signer)
       |
  Unix Socket IPC (JSON messages)
       |
  running xkey (IPC socket)
       |
  PIV Slot (9a, 9c, 9d, 9e)
       |
  Hardware Token (YubiKey, SoftHSM, etc.)
```

## PIV Slots

| Slot | Name | Typical Use |
|------|------|-------------|
| `9a` | Authentication | TLS client auth (default) |
| `9c` | Digital Signature | Document/code signing |
| `9d` | Key Management | Key agreement/wrapping |
| `9e` | Card Authentication | Physical access, contactless |

## Signer API

| Method | Description |
|--------|-------------|
| `NewSigner(config)` | Creates signer, fetches PIV cert to extract public key |
| `Public()` | Returns the public key from the PIV certificate |
| `Sign(rand, digest, opts)` | Delegates signing to xkey via IPC |
| `Certificate()` | Fetches the PIV slot certificate |
| `Close()` | Marks signer as closed (idempotent) |

Each `Sign` call opens a fresh Unix socket connection, sends the request, reads the response, and closes the connection. The 5-second IPC timeout (`ipcTimeout`, `pkg/xkeysigner/signer.go:38`) bounds both the dial and the exchange.

## TLS Helpers

| Function | Description |
|----------|-------------|
| `TLSCertificate(config)` | Returns `tls.Certificate` with xkey-backed private key |
| `TLSClientConfig(config)` | Returns `*tls.Config` for mTLS client connections |

```go
tlsConfig, err := xkeysigner.TLSClientConfig(&xkeysigner.TLSConfig{
    SignerConfig: &xkeysigner.SignerConfig{Slot: "9a"},
    CACertPEM:    caCert,
    ServerName:   "kms.example.com",
})
if err != nil {
    return err
}
conn, err := tls.Dial("tcp", "kms.example.com:8443", tlsConfig)
if err != nil {
    return err
}
```

## Socket Path Resolution

The socket path is resolved in order:

1. `SignerConfig.SocketPath` (explicit)
2. `$XKEY_IPC_SOCKET` environment variable
3. `$XDG_RUNTIME_DIR/xkey/xkey.sock`
4. `/tmp/xkey-$UID/xkey.sock`

## Configuration

```go
type SignerConfig struct {
    SocketPath string // override socket path
    Slot       string // PIV slot: "9a" (default), "9c", "9d", "9e"
}
```

## Error Reference

| Error | Condition |
|-------|-----------|
| `ErrSocketNotFound` | IPC socket does not exist |
| `ErrConnectionFailed` | Cannot connect or communicate |
| `ErrSignFailed` | Signing operation failed |
| `ErrUnsupportedHash` | Unsupported hash function in the signer options |
| `ErrClosed` | Operation on closed signer |
| `ErrInvalidSlot` | Invalid PIV slot identifier |
| `ErrNoCertificate` | No certificate in PIV slot |
| `ErrInvalidCertFormat` | Cannot parse certificate PEM/DER |
| `ErrNilPublicKey` | Certificate has no public key |
| `ErrNilConfig` | Nil config provided |
| `ErrTLSConfigFailed` | TLS config creation failed |

All errors are declared in `pkg/xkeysigner/errors.go`.

## Cross-References

- [PKCS#11 Module](../../../docs/pkcs11-provider-module/user.md) -- PKCS#11 token integration
- [TLS Configuration](../configuration/README.md) -- server TLS setup
