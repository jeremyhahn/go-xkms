# Client Configuration

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on where the ACME client GUI's configuration comes from.

The GUI has no Configuration view, and the client router has no `/config` or
`/renewal/*` endpoint. Configuration lives in the client's YAML config file,
which `Config` in `pkg/acme/client/service/config.go:30` loads. The GUI
changes it only by adding and removing accounts (`POST`/`DELETE
/api/v1/accounts`).

## Top-level keys (`Config`)

| Key | Purpose |
|-----|---------|
| `tenant_id` | Tenant the client acts for |
| `storage` | Where accounts and certificates are stored |
| `xkms` | Key backend |
| `logging` | Logging |
| `challenge` | Solver settings: `http01`, `dns01` (`config.go:257`) |
| `accounts` | Named ACME accounts |
| `certificates` | Named certificate specs |
| `devices` | Named TPM devices for enroll/attest |

## Certificate spec (`CertificateSpec`, `config.go:84`)

| Key | Purpose |
|-----|---------|
| `account` | Account name to issue under |
| `subject`, `sans` | Names on the certificate |
| `key` | Key parameters |
| `challenge` | Challenge type |
| `valid` | Requested validity |
| `deploy` | Where to write the issued certificate |
| `renewal` | `auto` (bool), `days_before` (int) (`CertRenewalConfig`, `config.go:122`) |
| `cross_signer` | Optional cross-signing |

Renewal is per certificate. There is no global renewal service setting.
