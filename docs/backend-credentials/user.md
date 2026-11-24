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

## Backend PIN strategy

The PIN of a PIN-protected PKCS#11 backend (`backends.pkcs11.pin`, and an
active `rng.pkcs11.pin`) is resolved at start-up by
`Server.resolveBackendPIN` (`pkg/server/backend_pin.go:71`) through
`pinselect.ResolveBackendPIN` (`pkg/pinselect/backendpin.go:141`). Every
refusal below stops `xkmsd` from starting (fail closed). Configure it with
`backend_pin` (`pkg/config/backend_pin.go`):

```yaml
backend_pin:
  strategy: auto     # auto (default), tpm2, sealed or manual
  minimum: tpm2      # optional: refuse to start below it
```

| Strategy | Where the PIN lives | When the backend starts |
|---|---|---|
| `auto` | `tpm2` when a TPM 2.0 is present, otherwise `sealed` | as the chosen strategy |
| `tpm2` | sealed to the TPM, whatever `credentials.seal_strategy` is | at start, or after unseal for a PIN stored elsewhere |
| `sealed` | sealed under the barrier, released at unseal; needs `credentials.seal_strategy: barrier` | after unseal |
| `manual` | not available yet: refused at start-up (see below) | — |

- **auto** picks `tpm2` when a TPM is present, otherwise `sealed`
  (`pkg/pinselect/backendpin.go`, `ResolveBackendPIN`). It never picks
  `sealed` on a TPM host. The i.MX 95 has no TPM and gets `sealed`.
- **The strategy must match where the PIN is stored.** The PIN is a
  `credential://` reference stored under `credentials.seal_strategy`:
  `sealed` needs `barrier`. Any other storage, such as a cloud KMS seal or
  the unset `manual` default, is refused with `BackendPINStoreError` before
  a record is written (`Server.backendPINStore`, `pkg/server/backend_pin.go`).
  `tpm2` (and `auto` on a TPM host) needs no second setting: a PIN not
  stored with `credentials.seal_strategy: tpm2` is read once after unseal,
  sealed to the TPM's Platform SRK, and the plaintext is wiped; every release
  unseals it from the TPM (`Server.tpmSealedBackendPINRelease`). If the TPM
  cannot seal it, start-up fails closed with `BackendPINTPMSealerError` and
  never falls back to `sealed`.
  While the credential is replaced, a transient `<name>-tpm2-staged`
  credential holds only the TPM-sealed blob; if start-up is interrupted
  mid-replacement, the next start completes it from that credential before
  config secrets resolve (`Server.recoverBackendPINCustody`), so the PIN is
  never lost.
  A persisted record is refused too if the storage has changed since it was
  written. Every release checks the storage again.
- **Minimum.** `minimum` orders `sealed` < `tpm2` < `manual`. A resolved
  strategy below it is refused with `BackendPINBelowMinimumError`
  (`pkg/pinselect/backendpin.go:183-185`).
- **Persisted record.** The first resolution writes the concrete strategy to
  `<PINDir>/backend-strategy`, where `<PINDir>` is
  `<datastore.path>/pin` (`pkg/pinselect/backendpin.go:186-189`,
  `pkg/server/backend_pin.go:46-48`). Later starts use that record. If
  you configure a strategy other than `auto` that disagrees with it, start-up
  is refused with `BackendPINMismatchError`
  (`pkg/pinselect/backendpin.go:163-169`). A strategy that is not available
  is refused with `BackendPINUnavailableError` and is never swapped for a
  weaker one, for example `tpm2` to `sealed` when the TPM is gone
  (`pkg/pinselect/backendpin.go:207-222`).
- **PKCS#11 self-store refusal.** PKCS#11 is never the store for its own
  PIN. `sealed` is refused with `ErrBackendPINSelfStore` when
  `barrier.strategy` or `credentials.seal_strategy` is `pkcs11`
  (`pkg/pinselect/backendpin.go:213-216`, `pkg/server/backend_pin.go:172-174`).
  This applies only to `sealed`: a PIN sealed to the TPM (`tpm2` with
  `credentials.seal_strategy: tpm2`) under `barrier.strategy: pkcs11` is not
  a self-store and resolves to `tpm2`
  (`TestResolveBackendPIN_TPM2UnderPKCS11BarrierIsNotSelfStore`,
  `pkg/server/backend_pin_test.go`).
- **rng.pkcs11.pin.** An active RNG PIN is held to the same policy even
  without the PKCS#11 key backend. It counts as active when `rng.pkcs11.pin`
  is set and `rng.mode` is `pkcs11`, `auto` or unset (unset means `auto`),
  or `rng.fallback_mode` is `pkcs11` (`rngPKCS11PINActive`,
  `pkg/server/backend_pin.go`).
- **manual is refused at start-up.** `strategy: manual`, `minimum: manual`
  and a `manual` record left by an earlier release all fail with
  `ErrBackendPINManualUnavailable`. This happens before anything is
  persisted or any token is opened (`pkg/server/backend_pin.go:42,97-100,123-126`).
  It stays refused until the unseal request carries a backend PIN: the go-qrdb
  sealed window does not carry one yet.
- **A Raft key on the token needs tpm2.** With
  `cluster.raft_enrollment.key_backend: pkcs11` the token opens before the
  Raft node starts, before unseal, when only `tpm2` can release the PIN.
  The strategy is resolved with a `tpm2` floor before that open, and
  `sealed`, `auto` resolving to `sealed`, a persisted `sealed` record or a
  lower minimum stop start-up with `ErrBackendPINNodeKeyBeforeUnseal`; no
  token opens and no record is written (`resolvePreNodeBackendPIN`,
  `pkg/server/backend_pkcs11.go`; `resolveBackendPINStrategy` and
  `preNodeBackendPINError`, `pkg/server/backend_pin.go`;
  `pkg/server/errors.go:67`).
- **Status.** The resolved strategy is reported as `backend_pin_strategy`.
  It is empty when no PKCS#11 PIN is in use
  (`Server.BackendPINStrategy`, `pkg/server/backend_pin.go:305-310`, wired at
  `pkg/server/server.go:979`). Read it over REST with
  `GET /api/v1/credentials/strategy` (`pkg/api/rest/handlers_credentials.go`)
  or over gRPC with `GetCredentialStrategy`
  (`pkg/api/grpc/service_credentials.go`).

See [`../plans/2262.md`](../plans/2262.md) for what is still open.
