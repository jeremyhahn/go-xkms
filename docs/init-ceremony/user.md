# Init Ceremony — User Guide

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-04

## Bootstrap a new server

1. Write `xkmsd.yaml` (storage, seal strategy, relying party).
2. Run `xkmsd init` with the Security Officer PIN and the factors the
   administrator will log in with:

   ```bash
   xkmsd init --config xkmsd.yaml --data-dir /var/lib/xkms \
     --hostname kms.example.com --so-pin "$XKMS_SO_PIN" --admin-factor mtls
   ```

3. Distribute `ca-bundle.pem` and the pin in `spki-pin.txt` to first-contact
   clients (`xkmsctl bootstrap`).
4. Keep `admin-key.pem` private; it is the administrator's mTLS credential.
5. Start the daemon: `xkmsd --config xkmsd.yaml`.

## Adding a security key

Pass `--admin-factor fido2` (and `--passkey-pin-stdin` if the key has a PIN).
With several keys attached, select one with `--passkey-device`. A missing key
fails before anything is changed, so retrying is safe.

## After a restart

A software (`passphrase`) barrier does not auto-unseal; unseal the node through
go-qrdb's barrier surface. Hardware strategies (`tpm2`, `pkcs11`) unseal
unattended.

## Holders and quorum

Holder enrolment and Shamir/quorum custody are go-qrdb's ceremony; consult the
go-qrdb documentation. xkms does not wrap it.
