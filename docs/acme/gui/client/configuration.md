# Client Configuration

The Configuration view (`GET /api/v1/config`, `PUT /api/v1/config`) manages the ACME client runtime settings.

## Settings

| Field | Type | Description |
|-------|------|-------------|
| `server_url` | string | ACME server directory URL |
| `account_url` | string | Registered account URL (set after registration) |
| `key_type` | string | Key algorithm (e.g., `RSA`, `ECDSA`) |
| `key_size` | number | Key size in bits (e.g., 2048, 4096) |
| `challenge_type` | string | Default challenge type (`http-01`, `dns-01`, `tls-alpn-01`, `device-attest-01`, `endorse-01`, `enroll-01`) |
| `auto_renew` | boolean | Enable automatic certificate renewal |
| `renew_before_days` | number | Days before expiry to trigger renewal |

## Auto-Renewal Configuration

The auto-renewal service runs in the background and periodically checks for certificates approaching expiry.

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | boolean | Whether the renewal service is active |
| `check_interval_hours` | number | Hours between renewal checks |
| `renew_before_days` | number | Days before expiry to trigger renewal |

Managed via `GET /api/v1/renewal/config` and `PUT /api/v1/renewal/config`.
