# MCP Protocol

Not served by xkmsd today.

`xkmsd` serves the ACME admin plane over REST only, mounted on its unified
mTLS listener (`cmd/xkmsd/admin.go:81`, `cmd/xkmsd/admin.go:130-171`; see
[REST Protocol](rest.md)). There is no MCP admin listener in `cmd/xkmsd`.

The SDK carries an MCP transport for the ACME admin client
(`sdk/go/acme/transport/mcp`), and `xkmsctl acme --acme-transport mcp`
accepts the flag (`cmd/xkmsctl/acme.go:64-74`), but pointing either at a
running `xkmsd` fails: there is nothing listening on the MCP side.

Wiring an MCP admin listener into `xkmsd` is tracked in go-xkms#743.

## See Also

- [Protocol Overview](README.md)
- [REST Protocol](rest.md)
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
