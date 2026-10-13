# Sealing and Barrier — User Guide

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-10-13

## What the barrier is

Everything the server stores is encrypted under one root key. The barrier is
what protects that root key. While the barrier is **sealed**, the root key is
unavailable and nothing that needs a key works. Unsealing releases it.

A freshly started server is sealed. That is normal.

## Choosing a strategy — the decision that lasts

You pick it once, at `barrier init`, and it is your deployment's security
posture from then on:

| Strategy | The root key is protected by | Unsealing needs |
|---|---|---|
| `tpm2` | the machine's TPM | the machine, in the same measured state |
| `pkcs11` | an HSM or token | the token, and its PIN, which this machine's TPM releases at boot |
| `awskms` / `gcpkms` / `azurekv` / `vault` | a cloud provider | the provider, reachable and authorized |
| `passphrase` | a passphrase | someone who knows it |
| `shamir` | M-of-N shares | M share-holders (enrolled and run through go-qrdb's holder/quorum ceremony, not `xkmsd init`) |
| `none` | nothing — encryption is off | nothing |

```
xkmsd init --barrier-strategy tpm2 --so-pin "$XKMS_SO_PIN"
xkmsd init --barrier-strategy passphrase --so-pin "$XKMS_SO_PIN"
```

**Nothing falls back.** If you initialize with `passphrase`, the barrier stays
`passphrase` even on a machine with a perfectly good TPM. And if a `tpm2`
barrier cannot reach its TPM, it does not quietly ask for a passphrase instead
— it stays sealed. That is deliberate: the alternative is a machine that comes
back up weaker than you think it is, with nothing to tell you.

`none` means what it says. It is for development.

## Unsealing

With `tpm2` or a cloud strategy you supply nothing — the hardware or the
provider releases the key, if the machine is still in the state it was sealed
against.

With `pkcs11` you supply nothing at boot either, once you have sealed the
token's PIN to this machine's TPM. Set `backends.pkcs11.library` and
`backends.pkcs11.token`, then run this once:

```
xkmsd seal-pkcs11-pin --config /etc/xkmsd/xkmsd.yaml < /run/secrets/token-pin
```

From then on, every `xkmsd run` releases the PIN from the TPM, logs in to the
token and unseals. The TPM releases the PIN only while the machine is in the
measured state it was in when you sealed it. After a firmware or boot change,
seal the PIN again. The PIN never appears in the config file or on a command
line.

With a cloud strategy, the server's own environment carries the provider
credentials (`awskms`, `gcpkms`, `azurekv`); the server must be built with the
strategy's build tag. `vault` takes its token from this machine's TPM in the
same way as the PKCS#11 PIN. Set `backends.vault`, then run this once:

```
xkmsd seal-vault-token --config /etc/xkmsd/xkmsd.yaml < /run/secrets/vault-token
```

A software strategy is unsealed through go-qrdb's own barrier surface;
xkms does not re-expose it.

There is one barrier: the database node's. The strategy you choose seals
that barrier, and every tenant's barrier sits beneath it. A server that uses a
remote datastore has no barrier of its own; the remote node seals the data.

## Sealing individual pieces of data

Separate from the barrier — this uses the backend's own mechanism:

```
xkmsctl can-seal --backend tpm2
xkmsctl seal "secret payload" --backend tpm2 --tpm-policy platform
xkmsctl unseal "$SEALED"
```

TPM sealing here is bound to what you name: `--tpm-policy platform` (or a
named policy) makes the data unseal only on a machine in the same measured
state, `--password` makes it unseal only with the password, and both makes the
password a recovery path inside the policy. A TPM seal with neither is
refused.

`--aad` binds context to the sealed value on every backend: unsealing
needs the same `--aad`. On `tpm2` the binding takes 48 of the 128 bytes a
sealed object holds, so at most 80 bytes seal with `--aad`. A value sealed on
`tpm2` or `vault` with `--aad` by an earlier release was not actually bound
(those releases dropped it): unseal it without `--aad` and seal it again.

Sealing belongs to your tenant. With `--key-id`, the key must be one of your
tenant's keys; another tenant's key reads as "key not found". Without it, a
software, PKCS#11 or cloud-KMS backend uses your tenant's own default sealing
key, created the first time you seal, so another tenant cannot unseal your
data even with the sealed blob in hand. A tenant account cannot seal on a TPM
2.0 backend: TPM-sealed data unseals for anyone who holds it, so only
platform accounts may use it.

## Keeping go-enclave keys in a TPM, HSM or KMS

A Go program that holds secrets with go-enclave can put its `Sealer`'s keys
under any backend go-xkms can seal with. Build the backend as usual, name a
sealing key on it, and choose a mode.

Per operation: every seal and open asks the backend, and the sealing key never
leaves it.

```go
protector, err := enclaveprovider.NewKeyProtector(backend, sealingKey)
if err != nil {
	return err
}
sealer, err := enclave.NewSealer(enclave.WithKeyProtector(protector))
```

Root key: the backend is asked once per start, for a root key you provisioned
once and stored.

```go
// Once, at setup: store sealedRoot wherever the program keeps its state.
sealedRoot, err := enclaveprovider.ProvisionRoot(ctx, backend, sealingKey)

// At every start:
unsealer, err := enclaveprovider.NewRootUnsealer(backend, sealingKey, sealedRoot)
if err != nil {
	return err
}
sealer, err := enclave.NewSealer(enclave.WithRootUnsealer(unsealer))
```

An open that fails with `enclave.ErrSealedAuthentication` means the stored
blob is not one this provider wrote under that key: do not retry. Any other
failure keeps the backend's own error — unreachable, refused, or a PCR policy
the machine no longer satisfies — and may succeed later.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| a `tpm2` barrier will not unseal after a firmware or boot change | the PCRs no longer match | this is the mechanism working; you need the recovery path |
| a `pkcs11` node will not boot: "the TPM refused to release platform/pkcs11-pin" | the platform PCRs changed since the PIN was sealed | check the change was expected, then run `xkmsd seal-pkcs11-pin` again |
| a `pkcs11` node will not boot: "no secret is sealed under platform/pkcs11-pin" | the PIN was never sealed on this machine | run `xkmsd seal-pkcs11-pin` |
| a cloud-strategy barrier will not unseal | the provider is unreachable or credentials expired | fix the **server's** environment |
| a cloud-strategy node will not boot: "is not compiled into this binary" | the server was built without that strategy's build tag | use a build that includes it |
| a `vault` node will not boot: "releasing the vault node seal token" | the token was never sealed on this machine, or the platform PCRs changed since | run `xkmsd seal-vault-token` |
| unseal fails with "could not unseal the root key" on a hardware or cloud strategy | the TPM, token or KMS key refused the root key: it is not the one the barrier was sealed under | point the server at the original TPM, token or key |
| `unseal` fails with "sealed data failed authentication" | the sealed value itself is wrong: modified, cut short, from another key or backend, or unsealed with different `--aad` than it was sealed with | do not retry — find where the value came from |
| `unseal` fails with any other error | not proven either way: usually the environment (unreachable, permission, PCR), but a backend whose own error is ambiguous — a PKCS#11 token answering `CKR_GENERAL_ERROR`, as SoftHSM before 2.7.0 does for a modified value — reports bad data this way too | read the cause in the message; fix the environment if it names one, otherwise check the value and `--aad` as well |
| you have no credential and no recovery keys | there is no way in | the root key is unrecoverable — this is what a barrier is |

That last row is not a bug. Plan for it before you need it: use a quorum with
enough holders, and make sure the shares are not all in one place.

## Where to go next

- The hardware behind the strategy: [`../crypto-backends/user.md`](../crypto-backends/user.md)
- PINs and lockout: [`../pin-management/user.md`](../pin-management/user.md)
- First-boot setup: [`../init-ceremony/user.md`](../init-ceremony/user.md)
