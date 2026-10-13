# Sealing and Barrier — CLI

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-10-13

Binary: `xkmsctl`. The top-level `seal` / `unseal` / `can-seal` data verbs. Global flags: [`../key-management/cli.md`](../key-management/cli.md).

`xkmsctl barrier` was removed: the barrier is go-qrdb's, and xkms does not
re-expose its verbs. Only the data-level sealing verbs below remain.

## Data-level sealing

Separate from the barrier: sealing an arbitrary payload with a backend's native
mechanism.

| Verb | Args | Purpose |
|---|---|---|
| `seal <data>` | data | Seal with the backend's mechanism |
| `unseal <ciphertext>` | ciphertext | Unseal |
| `can-seal` | — | Whether the current backend can seal |

```
xkmsctl can-seal --backend tpm2
xkmsctl seal "secret payload" --backend tpm2 --tpm-policy platform
xkmsctl seal "secret payload" --backend software --key-id vault-key
```

On `tpm2` a seal must name `--tpm-policy`, `--password` or both; a seal with
neither is refused (`ErrSealUnprotected`), because nothing would protect the
object. With a policy, the password counts only inside it. See
[`../tpm2/engineering.md`](../tpm2/engineering.md) §"Object
authorization".

`--aad` binds additional authenticated data on every backend, `tpm2` and
`vault` included; `unseal` must present the same `--aad`. On `tpm2` at most 80
bytes of data seal with `--aad`.

```
xkmsctl seal "secret payload" --backend tpm2 --tpm-policy platform --aad volume=root
xkmsctl unseal "$SEALED" --backend tpm2 --aad volume=root
```

An unseal that fails because the backend established that the sealed value
is wrong — modified, truncated, from another key or backend, or a different
`--aad` — prints an error beginning `sealed data failed authentication`;
retrying it will not help. Any other error is not proof of an outage: a
backend whose own answer is ambiguous (a PKCS#11 token returning
`CKR_GENERAL_ERROR`, as SoftHSM before 2.7.0 does for a modified value)
reports bad data without that prefix.

`--key-id` names one of the calling tenant's keys; without it the tenant's
own default sealing key is used. A tenant account is refused on `tpm2`
(see [`api.md`](api.md) §"Data-level sealing is tenant-scoped").

## Node seal secrets: `xkmsd seal-pkcs11-pin`, `xkmsd seal-vault-token`

Binary: `xkmsd`. Two node seals need a secret before the node's barrier, or
anything behind it, is open: `pkcs11` logs in to its token with the user PIN,
and `vault` authenticates to Transit with a token. Each verb seals its secret
into the pre-barrier store, so that `xkmsd run` with the matching
`barrier.strategy` unseals the node with no operator present. Run it once,
and again whenever the secret or the platform PCRs change.

| Verb | Secret | Store key | Released by |
|---|---|---|---|
| `seal-pkcs11-pin` | PKCS#11 token user PIN | `platform/pkcs11-pin` | `barrier.strategy: pkcs11` |
| `seal-vault-token` | Vault token | `platform/vault-token` | `barrier.strategy: vault` |

| Flag | Default | Meaning |
|---|---|---|
| `--config string` | none (required) | The configuration `xkmsd run` loads; the TPM (`backends.tpm2`) and the store directory (`<datastore.path>/preseal`) come from it |

The secret is read from standard input, with its trailing newline removed.
There is no flag form. The TPM must have the Platform SRK enrolled.

```
xkmsd seal-pkcs11-pin --config /etc/xkmsd/xkmsd.yaml < /run/secrets/token-pin
xkmsd seal-vault-token --config /etc/xkmsd/xkmsd.yaml < /run/secrets/vault-token
```

Errors: `ErrSealSecretConfigRequired` (no `--config`), `ErrSealSecretEmpty`,
`ErrSealSecretReadFailed`, or a wrapped `*embeddednode.NodeSealError` naming
the store or TPM step that failed. A later boot that cannot release the
secret fails closed with `*preseal.RefusedError` (the platform PCRs changed)
or `*preseal.NotFoundError` (the secret was never sealed).

The cloud KMS node seals (`awskms`, `gcpkms`, `azurekv`) have no verb: they
authenticate with the provider's ambient credentials.

## go-enclave provider

No CLI surface: the go-enclave provider bridge (`pkg/enclaveprovider`) is a
library seam that a Go program wires into its own go-enclave `Sealer`. See
[`api.md`](api.md) §"go-enclave provider".

## TPM policies

`xkmsctl policy` was removed with the PCR snapshot store. Named TPM policies
are managed with `xkmsctl tpm policy`; a TPM2 seal binds to one with
`seal --tpm-policy`. See [`../tpm-policies/cli.md`](../tpm-policies/cli.md).

## Exit codes

`0` on success. A sealed barrier is not an error from `barrier status` — it is a
reported state. Unseal failures are non-zero and never partial. `policy verify`
is non-zero when the policy no longer matches current PCR values.

## Parity coverage

`CommandDefinition` entries exist for `seal`, `unseal`, `can-seal`, and (as of
go-xkms#691) every `policy` verb.

**Defect:** none of the `barrier` verbs — `status`, `init`, `init-shamir`,
`unseal`, `unseal-shares`, `seal`, `rekey`, the four `recovery` verbs, or
`enable-encryption` — has a definition in
`test/integration/api/commands/commands.go`, despite all of them having routes
on four transports.
