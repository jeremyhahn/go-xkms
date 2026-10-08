# Init Ceremony — CLI

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-04

Binary: `xkmsd`. Command: `xkmsd init`. Source: `cmd/xkmsd/init.go`.

`xkmsctl init`, `xkmsctl ceremony` and `xkmsctl barrier` no longer exist; the
holder/quorum ceremony is go-qrdb's own surface, served by the node.

| Flag | Meaning |
|---|---|
| `--config` | Daemon configuration file (default `/etc/xkms/xkmsd.yaml`) |
| `--so-pin` | Security Officer PIN (required; `XKMS_SO_PIN`) |
| `--barrier-strategy` | `passphrase`, `pkcs11`, `tpm2`, `awskms`, `gcpkms`, `azurekv`, `vault` (default `passphrase`) |
| `--data-dir` | Directory for the public artifacts |
| `--hostname` | FQDN written into the administrator/server certificate |
| `--sans` | Comma-separated additional DNS/IP SANs |
| `--admin-factor` | Login factor to enroll; repeatable or comma-separated (`mtls`, `piv`, `pkcs11`, `fido2`; default `mtls`) |
| `--passkey-device` | Pick one FIDO2 authenticator when several are attached |
| `--passkey-pin-stdin` | Read the authenticator PIN from standard input |

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml --data-dir /var/lib/xkms \
  --hostname kms.example.com --so-pin "$XKMS_SO_PIN" --admin-factor mtls
```

Outputs in `--data-dir`: `ca-bundle.pem`, `spki-pin.txt`, `admin-cert.pem`,
`admin-key.pem`. Exit code 0 on success, 1 on any failure.
