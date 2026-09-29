# QUIC Protocol

Not served by xkmsd today.

`xkmsd` serves the ACME admin plane over REST only, mounted on its unified
mTLS listener (`cmd/xkmsd/admin.go:81`, `cmd/xkmsd/admin.go:130-171`; see
[REST Protocol](rest.md)). There is no QUIC admin listener in `cmd/xkmsd`.

The SDK carries a QUIC transport for the ACME admin client
(`sdk/go/acme/transport/quic`), and `xkmsctl acme --acme-transport quic`
accepts the flag (`cmd/xkmsctl/acme.go:64-74`), but pointing either at a
running `xkmsd` fails: there is nothing listening on the QUIC side.

Wiring a QUIC admin listener into `xkmsd` is tracked in go-xkms#743.

## See Also

- [Protocol Overview](README.md)
- [REST Protocol](rest.md)
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
