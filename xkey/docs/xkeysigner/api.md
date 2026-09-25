# xkeysigner — API

> **Status: NORMATIVE** · Feature: `xkeysigner` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

Two APIs, at two different layers.

## The Go API: `crypto.Signer`

`*xkeysigner.Signer` implements the standard library's `crypto.Signer`
(`Public() crypto.PublicKey`, `Sign(rand io.Reader, digest []byte, opts
crypto.SignerOpts) ([]byte, error)`), so it drops into anything that
accepts one — most directly `tls.Certificate.PrivateKey`, which is exactly
how `xkeysigner.TLSCertificate` uses it (`engineering.md`). There is no
xkeysigner-specific API contract beyond that standard interface plus
`Certificate()` and `Close()`.

```go
tlsConfig, err := xkeysigner.TLSClientConfig(&xkeysigner.TLSConfig{
    SignerConfig: &xkeysigner.SignerConfig{Slot: "9a"},
    CACertPEM:    caCertPEM,
    ServerName:   "xkms.example.com",
})
if err != nil {
    // handle error
}
conn, err := tls.Dial("tcp", "xkms.example.com:8443", tlsConfig)
```

Or, from a go-xkms SDK client, without touching `xkeysigner` directly:

```go
client, err := xkms.NewWithOptions(
    xkms.WithXKeyAuth(""), // empty: resolves $XKEY_IPC_SOCKET or the platform default
)
```

## The wire API: local IPC only

The JSON-over-Unix-socket protocol between `xkeysigner.Signer` and the
xKey GUI's `PKCS11IPCHandler` is **not** a network API — no REST or gRPC
endpoint, no listener reachable off the local host. It is fully specified
in `engineering.md` ("Wire format") and is not meant to be called by
anything other than this package; the socket path and message shapes are
xkey/go-xkms internal contract, not a published integration surface.
