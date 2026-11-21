# Backend Credentials — User Guide

> **Status: NORMATIVE** · Feature: `backend-credentials` · Repo: `go-xkms` · Last verified: 2026-10-12

Backend credentials are the secrets a crypto backend needs before it can
start: the PKCS#11 User PIN, a cloud KMS secret, a Vault token. `xkmsd`
keeps them in a credential service under one **seal strategy**, and the
backend config refers to them by name with `credential://<name>`.

## Choose a strategy

Set it in the `xkmsd` config. This is the only key under `credentials:`
(`pkg/config/config.go:272-283`):

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

```
xkmsctl credential list --server https://kms.example.com:8443 \
  --tls-cert admin.pem --tls-key admin-key.pem --tls-ca ca.pem
```

The response contains names only. No API returns a credential's value.
Under a hardware or cloud strategy the value is stored as the platform
secret `credentials/<name>`, but the platform-secrets commands refuse that
name with a permission error and leave it out of their listing.

## Backend PIN strategy (in progress, #2262)

> **Status: in progress.** xkmsd resolves and persists the strategy at
> start-up (fail closed), starts the PKCS#11 backend after unseal under
> `sealed`, zeroizes the held PIN at shutdown, and reports the strategy as
> `backend_pin_strategy` in `GET /api/v1/credentials/strategy` (REST and
> MCP; not yet gRPC). Not yet wired: the manual PIN on the unseal request
> (the go-qrdb sealed window carries no backend PIN) and the PKCS#11 open
> before the Raft node starts. See [`../plans/2262.md`](../plans/2262.md).

The PIN of a PIN-protected PKCS#11 backend (`backends.pkcs11.pin`,
`rng.pkcs11.pin`) is resolved by `pinselect.ResolveBackendPIN`
(`pkg/pinselect/backendpin.go`) under one strategy
(`pkg/config/backend_pin.go`):

```yaml
backend_pin:
  strategy: auto     # auto (default), tpm2, sealed or manual
  minimum: tpm2      # optional: refuse to start below it
```

| Strategy | Where the PIN lives | When the backend starts |
|---|---|---|
| `auto` | `tpm2` when a TPM 2.0 is present, otherwise `sealed` (the i.MX 95 selects `sealed`) | as the chosen strategy |
| `tpm2` | sealed to the TPM | at start |
| `sealed` | sealed under the barrier, released at unseal | after unseal |
| `manual` | never stored: supplied with the unseal request, memory only, zeroized at seal | after unseal; stops at seal |

- `pkcs11` is refused: PKCS#11 is never the store of its own PIN, and
  `sealed` is refused when the barrier key itself is on that backend
  (`ErrBackendPINSelfStore`).
- The first resolution persists the concrete strategy in
  `<data dir>/pin/backend-strategy`; later starts use it, a configured
  strategy that disagrees is refused (`BackendPINMismatchError`).
- An unavailable strategy fails closed (`BackendPINUnavailableError`); it
  never downgrades, for example from `tpm2` to `sealed` when the TPM is
  gone.
- `minimum` orders `sealed` < `tpm2` < `manual`
  (`BackendPINBelowMinimumError`).
