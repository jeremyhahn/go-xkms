# CA Admin GUI

> **Correction (go-xkms#942):** there is no `cactl` binary in this
> repository, and this package (`pkg/acme/gui/admin`) has no confirmed
> `cmd/` entry point — see the correction in [`../README.md`](../README.md).
> The desktop content below describes what this package would do if
> wired up; treat it as unverified against a running binary.

The admin GUI provides certificate authority management through a desktop application and (a separately implemented) web interface — see the correction above.

## Desktop Mode

Not currently reachable from any binary in this repository — see the
correction above.

### Window Defaults

| Property | Value |
|----------|-------|
| Title | Trusted CA Admin |
| Size | 1280 x 800 |
| Min Size | 1024 x 700 |

### Connection Defaults

Unverified — see the correction above.

## Web Mode

The web admin UI that is actually wired today is `xkmsd`'s own
`/admin-ui` (`pkg/acme/web/packages/admin`, `cmd/xkmsd/admin.go:73`), not
`/ui/admin/`. See the correction at the top of this page.

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
