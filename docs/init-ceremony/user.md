# Init Ceremony — User Guide

> **Status: NORMATIVE** · Feature: `init-ceremony` · Repo: `go-xkms` · Last verified: 2026-10-04

## Bootstrap a new server

1. Write `xkmsd.yaml` (storage, seal strategy, relying party) with
   `datastore.path` set to the durable directory, the same one step 2 passes
   as `--data-dir` (here `/var/lib/xkms`), so `xkmsd init` and `xkmsd run`
   share one datastore and `xkmsd run` accepts the administrator's
   certificate (the ceremony root init wrote joins its client CAs).
   `--data-dir` is only the fallback for an empty `datastore.path` and the
   directory init writes its artifacts to.
2. Run `xkmsd init` with the Security Officer PIN and the factors the
   administrator will log in with:

   ```bash
   xkmsd init --config xkmsd.yaml --data-dir /var/lib/xkms \
     --hostname kms.example.com --so-pin "$XKMS_SO_PIN" --admin-factor mtls
   ```

3. Keep `/var/lib/xkms/ca-bundle.pem` (the bundle init writes under
   `--data-dir`) on the server: it is the client-authentication root the
   administrator's client certificate chains to, not a server-trust anchor,
   and `/var/lib/xkms/spki-pin.txt` is the pin of that ceremony root. The
   ceremony CA key is gone when init exits.
4. Keep `admin-key.pem` private; it is the administrator's mTLS credential.
5. Start the daemon: `xkmsd --config xkmsd.yaml`.
6. Give clients the running server's trust material. Take the server's TLS
   certificate, compute its pin and distribute the pin out of band; clients
   then fetch the server's bundle from `/v1/ca/bootstrap`
   (see [Trust Bootstrap](../trust-bootstrap/user.md)):

   ```bash
   openssl s_client -connect kms.example.com:8443 </dev/null | openssl x509 > kms.crt
   xkmsctl bootstrap spki show-pin --cert-file kms.crt   # PIN = the printed pin
   xkmsctl bootstrap auto --server-url https://kms.example.com:8443 \
     --spki-pin "$PIN" --bundle-path /v1/ca/bootstrap --bundle-output ca-bundle.pem
   ```

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
