# xkeysigner — Engineering

> **Status: NORMATIVE** · Feature: `xkeysigner` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

`pkg/xkeysigner` lives in the **root `go-xkms` module**
(`github.com/jeremyhahn/go-xkms/pkg/xkeysigner`), not `xkey`; it is
documented in this folder because its only reason to exist is xkey's
GUI-side IPC daemon (`architecture.md`), and `xkey/docs/README.md` tracks
it as one of the product's feature folders.

## Exported surface

### `pkg/xkeysigner` (`signer.go`, `tls.go`)

| Symbol | Kind | Notes |
|---|---|---|
| `xkeysigner.SignerConfig` | type | `SocketPath string`, `Slot string` |
| `xkeysigner.NewSigner(config *SignerConfig) (*Signer, error)` | func | resolves socket path and slot, fetches the certificate to extract the public key |
| `xkeysigner.Signer` | type | implements `crypto.Signer` |
| `(*Signer).Public() crypto.PublicKey` | method | — |
| `(*Signer).Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)` | method | `rand` is ignored (signing happens on the far side of the IPC call); `digest` must be pre-hashed |
| `(*Signer).Certificate() (*x509.Certificate, error)` | method | fetches and parses the PIV slot certificate |
| `(*Signer).Close() error` | method | idempotent; marks the signer closed, `Sign`/`Certificate` return `ErrClosed` after |
| `xkeysigner.TLSConfig` | type | `SignerConfig *SignerConfig`, `CACertPEM []byte`, `ServerName string` |
| `xkeysigner.TLSCertificate(config *SignerConfig) (*tls.Certificate, error)` | func | `tls.Certificate{Certificate: [cert.Raw], PrivateKey: signer, Leaf: cert}` |
| `xkeysigner.TLSClientConfig(config *TLSConfig) (*tls.Config, error)` | func | `MinVersion: tls.VersionTLS13`; adds `CACertPEM` to `RootCAs` and `ServerName` when set |

`Public()`, `Sign()`, and `Certificate()` all check `s.closed` first
(`atomic.Bool`) and return `ErrClosed`, so a `Signer` is safe to `Close()`
from a different goroutine than the one calling `Sign`.

### `sdk/go` — the xkey wiring

| Symbol | Kind | Notes |
|---|---|---|
| `xkms.WithXKeyAuth(socketPath string) Option` | func | `sdk/go/options.go:255-275`; empty `socketPath` falls back to `$XKEY_IPC_SOCKET` |
| `xkms.ErrXKeyAuthFailed` | var | returned by `WithXKeyAuth` when `xkeyAuthResolver.ResolveTLSConfig` fails |
| `xkeyAuthResolver` (unexported) | type | `sdk/go/xkey_auth.go`; `ResolveTLSConfig() (*tls.Config, error)`, `HasCertificate() bool` — both always request PIV slot `9a` |

`WithXKeyAuth` sets `opts.tlsConfig` and `opts.tlsEnabled = true` on the
client options; it is one functional option among the others in
`sdk/go/options.go` (`WithJWTToken`, `WithHeaders`, ...) and composes with
`NewWithOptions` the same way.

## Wire format

JSON over a Unix domain socket, one request/response pair per connection
(`signer.go:73-126`):

```go
type ipcMessage struct {
    Type   string     `json:"type"`             // "pkcs11"
    PKCS11 *ipcPKCS11 `json:"pkcs11,omitempty"`
}
type ipcPKCS11 struct {
    Action  string         `json:"action"`        // "sign" | "get_piv_certificate"
    Sign    *ipcSignParams `json:"sign,omitempty"`
    PIVCert *ipcPIVCert    `json:"piv_cert,omitempty"`
}
type ipcSignParams struct {
    Backend string `json:"backend"`
    KeyID   string `json:"key_id"`               // "piv-" + slot, e.g. "piv-9a"
    Data    string `json:"data"`                 // base64
    Hash    string `json:"hash,omitempty"`        // "SHA-256" | "SHA-384" | "SHA-512"
}
type ipcPIVCert struct {
    Backend string `json:"backend"`
    Slot    string `json:"slot"`
    Format  string `json:"format,omitempty"`      // "pem"
}
```

This is the client-side half of `xkey/pkg/ipc`'s `MessageTypePKCS11`
protocol (`ipc.PKCS11Payload`, `ipc.SignParams`, `ipc.PIVCertParams`, ...,
`xkey/pkg/ipc/pkcs11_types.go`); the server side that answers it is
`services.PKCS11IPCHandler` (`architecture.md`).

## Errors (`pkg/xkeysigner/errors.go`)

| Sentinel | Condition |
|---|---|
| `xkeysigner.ErrSocketNotFound` | `net.DialTimeout` got `os.IsNotExist` — no GUI IPC server listening |
| `xkeysigner.ErrConnectionFailed` | dial, deadline, encode, or decode failed for any other reason |
| `xkeysigner.ErrSignFailed` | response status was not `"ok"`, or the sign result was missing |
| `xkeysigner.ErrClosed` | `Sign`/`Certificate` called after `Close()` |
| `xkeysigner.ErrInvalidSlot` | slot not one of `9a`/`9c`/`9d`/`9e` |
| `xkeysigner.ErrNoCertificate` | response status was not `"ok"`, the PIV cert result was missing, or the certificate PEM was empty |
| `xkeysigner.ErrInvalidCertFormat` | PEM did not decode, or the DER did not parse as an `x509.Certificate` |
| `xkeysigner.ErrNilPublicKey` | the parsed certificate had a nil public key |
| `xkeysigner.ErrNilConfig` | `nil` passed to `NewSigner`, `TLSCertificate`, or `TLSClientConfig` |
| `xkeysigner.ErrTLSConfigFailed` | declared, but **not returned by any function in this package today** — `errors.go:46-47` defines it; no call site in `signer.go`/`tls.go` constructs it. Documented as-is rather than assumed to mean something. |

## Socket path resolution

In order (`signer.go:136-142, 308-318`):

1. `SignerConfig.SocketPath` (explicit)
2. `$XKEY_IPC_SOCKET`
3. `$XDG_RUNTIME_DIR/xkey/xkey.sock`
4. `/tmp/xkey-$UID/xkey.sock`

The fallback is a deliberately independent re-implementation of the same
logic in `xkey/pkg/ipc/socket.go`'s `DefaultSocketPath()` — comment at
`signer.go:308-311` states why: avoiding a circular import from the root
module back into `xkey`.

## Tests

| Layer | File | What it proves |
|---|---|---|
| `pkg/xkeysigner` | `signer_test.go` | valid/nil/default config resolution, all four valid slots, invalid slot, connection failure, `Public`/`Sign`/`Certificate` success and every error path above, `Close` idempotency, `itoa` |
| `pkg/xkeysigner` | `tls_test.go` | `TLSCertificate`/`TLSClientConfig` success, nil config, no certificate available, invalid slot, CA cert / server name wiring, invalid/empty CA PEM |
| `sdk/go` | `xkey_auth_test.go` | `WithXKeyAuth` success/empty-path/no-server, `xkeyAuthResolver.ResolveTLSConfig`/`HasCertificate` true and false paths |
