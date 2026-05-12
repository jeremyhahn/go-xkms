# CA Admin GUI

The admin GUI provides certificate authority management through both a desktop application (`cactl`) and a web interface hosted by the ACME server at `/ui/admin/`.

## Desktop Mode

```bash
# Launch admin desktop GUI (no subcommand = GUI mode)
./bin/cactl
```

### Window Defaults

| Property | Value |
|----------|-------|
| Title | Trusted CA Admin |
| Size | 1280 x 800 |
| Min Size | 1024 x 700 |
| Linux Program Name | `cactl` |

### Connection Defaults

| Property | Value |
|----------|-------|
| Transport | `unix` |
| Address | `/run/trusted-ca-grpc.sock` |
| Timeout | 30 seconds |

The admin desktop app connects to the CA server via an `AdapterFactory` that supports all protocols: Unix socket, REST, gRPC, QUIC, and MCP. Configure via the Connection Settings view or CLI flags.

## Web Mode

The ACME server embeds the admin SPA and serves it at `/ui/admin/`. Access it in any browser:

```
https://your-ca-server:8443/ui/admin/
```

See [Web Mode](web-mode.md) for details.

## Navigation Views

| View | Description |
|------|-------------|
| Dashboard | CA status, certificate/account statistics |
| Certificates | List, view, and revoke certificates |
| Accounts | List and manage ACME accounts |
| Tenants | Multi-tenant CA management |
| Connection | Protocol and server connection settings (desktop only) |
| Settings | Application preferences |

## Related Documentation

- [Views Reference](views.md)
- [Web Mode](web-mode.md)
- [Admin API Reference](api.md)
