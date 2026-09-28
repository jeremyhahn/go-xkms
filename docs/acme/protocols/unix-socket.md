# Unix Socket Protocol

Not served by xkmsd today, and not reachable from `xkmsctl acme`.

`xkmsd` serves the ACME admin plane over REST only, mounted on its unified
mTLS listener (`cmd/xkmsd/admin.go:81`, `cmd/xkmsd/admin.go:130-171`; see
[REST Protocol](rest.md)). There is no Unix-socket admin listener in
`cmd/xkmsd`.

Unlike the gRPC, QUIC, and MCP transports, the ACME admin plane's Unix
adapter is explicitly rejected at the client, not merely unwired at the
server: `acmeClientOptions` refuses both `unix://` addresses and
`--acme-transport unix` with `ACMEAdminUnsupportedTransportError`
(`cmd/xkmsctl/acme.go:283-306`). The SDK still carries a Unix-domain-socket
route registry for admin endpoints (`sdk/go/acme/transport/unix`), mapping
the same `/admin/...` and `/api/v1/tenants/...` paths REST uses, but nothing
in `cmd/xkmsd` or `cmd/xkmsctl` connects it end to end today.

Wiring a Unix-socket admin listener into `xkmsd`, and accepting it from
`xkmsctl acme`, is tracked in go-xkms#743.

## See Also

- [Protocol Overview](README.md)
- [REST Protocol](rest.md)
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
