# ACME Client GUI

The ACME client GUI is a desktop application built with Wails v2 that provides a graphical interface for all ACME client operations: account registration, certificate lifecycle management, device enrollment/attestation, and auto-renewal configuration.

## Launch

```bash
# No subcommand = GUI mode
./bin/trusted-acme-client
```

## Window Defaults

| Property | Value |
|----------|-------|
| Title | Trusted ACME Client |
| Size | 1024 x 768 |
| Min Size | 800 x 600 |
| Linux Program Name | `trusted-acme-client` |

## Navigation Views

| View | Description |
|------|-------------|
| Dashboard | Overview of client status and recent activity |
| Register | ACME account registration with EAB support |
| Request Cert | Request new certificates for domains |
| Renew Cert | Manually renew an existing certificate |
| Revoke Cert | Revoke a certificate by serial number |
| Auto-Renewal | Configure and monitor automatic certificate renewal |
| Device Enroll | TPM device enrollment with EK certificate |
| Device Attest | TPM-based remote attestation |
| Configuration | Client settings (server URL, key type, challenge type) |
| Challenges | Per-challenge-type configuration |
| Settings | Application preferences |

## Related Documentation

- [Views Reference](views.md)
- [Configuration Guide](configuration.md)
- [Challenge Types](challenge-types.md)
- [Embedded API Reference](api.md)
