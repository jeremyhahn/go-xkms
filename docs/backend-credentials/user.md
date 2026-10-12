# Backend Credentials — User Guide

> **Status: NORMATIVE** · Feature: `backend-credentials` · Repo: `go-xkms` · Last verified: 2026-10-11

Backend credentials are the secrets a crypto backend needs before it can
start: the PKCS#11 User PIN, a cloud KMS secret, a Vault token. `xkmsd`
keeps them in a credential service under one **seal strategy**, and the
backend config refers to them by name with `credential://<name>`.

## Choose a strategy

Set it in the `xkmsd` config. This is the only key under `credentials:`
(`pkg/config/config.go:271-282`):

```yaml
credentials:
  seal_strategy: manual   # the default
```

| Strategy | Restarts unattended? | What you need |
|---|---|---|
| `manual` | No. Values are held in memory and are gone after a restart | Nothing |
| `barrier` | Yes, once the barrier is unsealed | `datastore.mode: standalone` (or unset) and `barrier.enabled: true`; any other combination is refused when the config loads |
| `tpm2` | Yes, while the platform's PCR state matches | A TPM with an enrolled Platform SRK. See [`../tpm2/`](../tpm2/) |
| `awskms` / `gcpkms` / `azurekv` | Yes | A `backends.awskms` / `backends.gcpkms` / `backends.azurekv` section, and an `xkmsd` built with that tag |
| `pkcs11`, `vault`, `passphrase` | — | **Not usable in `xkmsd` today.** Startup fails with "platform store strategy unavailable" |

For the source behind each row, see [`architecture.md`](architecture.md)
§"What `xkmsd` actually builds".

## Point a backend at a credential

Any of these five fields can hold a `credential://<name>` reference:
`backends.pkcs11.pin`, `rng.pkcs11.pin`, `backends.awskms.secret_key`,
`backends.azurekv.client_secret` and `backends.vault.token`. They are
resolved at startup, before the backends start
(`pkg/server/secret_wiring.go:62-69`).

```yaml
backends:
  pkcs11:
    pin: credential://pkcs11-user-pin
```

## Check the strategy

```
xkmsctl credential strategy --server https://kms.example.com:8443 \
  --tls-cert admin.pem --tls-key admin-key.pem --tls-ca ca.pem
```

`Auto-unseal: true` means the server can read its credentials without you,
which is true for every strategy except `manual`.

## Submit or rotate a credential

```
xkmsctl credential submit --server https://kms.example.com:8443 \
  --tls-cert admin.pem --tls-key admin-key.pem --tls-ca ca.pem \
  --name pkcs11-user-pin --value "$USER_PIN"
```

To rotate, submit the same name again. Under `manual`, a name can be
submitted only once per run, and a second submit is refused with a conflict
error.

Your identity must be platform-scoped. A tenant administrator gets
"not found".

## See what is still outstanding

`xkmsctl credential list` currently gets a 404 from `xkmsd` (see
[`cli.md`](cli.md) §"Known gap"). Until that is fixed, call the route
directly:

```
curl --cert admin.pem --key admin-key.pem --cacert ca.pem \
  https://kms.example.com:8443/api/v1/credentials/
```

The response contains names only. The credential API never returns a value.
Under a hardware or cloud strategy, though, a platform-scoped caller with
platform-secrets read permission can read the stored entry
`credentials/<name>` through [`../platform-secrets/`](../platform-secrets/).
Grant that permission accordingly.
