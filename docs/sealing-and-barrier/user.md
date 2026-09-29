# Sealing and Barrier — User Guide

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-09-28

## What the barrier is

Everything the server stores is encrypted under one root key. The barrier is
what protects that root key. While the barrier is **sealed**, the root key is
unavailable and nothing that needs a key works. Unsealing releases it.

A freshly started server is sealed. That is normal.

## The first command to run when anything is broken

```
xkmsctl barrier status
```

Most "the server is broken" reports are a sealed barrier. This is the cheapest
check there is.

## Choosing a strategy — the decision that lasts

You pick it once, at `barrier init`, and it is your deployment's security
posture from then on:

| Strategy | The root key is protected by | Unsealing needs |
|---|---|---|
| `tpm2` | the machine's TPM | the machine, in the same measured state |
| `pkcs11` | an HSM or token | the token, and its PIN |
| `awskms` / `gcpkms` / `azurekv` / `vault` | a cloud provider | the provider, reachable and authorized |
| `passphrase` | a passphrase | someone who knows it |
| `shamir` | M-of-N shares | M share-holders |
| `none` | nothing — encryption is off | nothing |

```
xkmsctl barrier init --barrier-strategy tpm2 --user-pin -
xkmsctl barrier init --barrier-strategy passphrase --passphrase -
xkmsctl barrier init-shamir --threshold 3 --total 5
```

**Nothing falls back.** If you initialize with `passphrase`, the barrier stays
`passphrase` even on a machine with a perfectly good TPM. And if a `tpm2`
barrier cannot reach its TPM, it does not quietly ask for a passphrase instead
— it stays sealed. That is deliberate: the alternative is a machine that comes
back up weaker than you think it is, with nothing to tell you.

`none` means what it says. It is for development.

## Unsealing

```
xkmsctl barrier unseal --passphrase -
xkmsctl barrier unseal-shares --share "$S1" --share "$S2" --share "$S3"
```

With `tpm2` or a cloud strategy you supply nothing — the hardware or the
provider releases the key, if the machine is still in the state it was sealed
against.

## Shamir shares: write them down at init

`barrier init-shamir` prints the shares **once**. There is no command to list
them later, and there never will be — a server that could hand out its own
shares would not be protecting anything.

```
xkmsctl barrier init-shamir --threshold 3 --total 5
```

Distribute them to different people in different places. Three of five means any
three can unseal, and any two cannot.

## Sealing on purpose

```
xkmsctl barrier seal --so-pin -
```

Everything stops until it is unsealed. That is the point — it is the response to
a suspected compromise.

## Recovery keys, and why to think twice

```
xkmsctl barrier recovery generate --threshold 2 --total 3 --so-pin -
xkmsctl barrier recovery recover --share "$R1" --share "$R2"
xkmsctl barrier recovery delete-keys
```

Recovery keys are a **second door** into the barrier that does not need the
primary credential. That is useful when the primary credential is lost, and it
is a complete bypass in the hands of anyone who finds them. Storing them next to
the server is equivalent to not having a barrier. `delete-keys` closes the door
again once the emergency is over.

## Rotating the root key

```
xkmsctl barrier rekey --so-pin -
```

New root key, re-sealed. **Old shares and old recovery keys stop working** —
redistribute before you need them.

## Turning encryption on later

If a barrier was initialized `none`:

```
xkmsctl barrier enable-encryption --strategy passphrase --passphrase - \
    --mechanism swap --availability quiesced
```

Defaults are the cautious ones: `swap` stages the re-encryption, `quiesced`
stops writes during it. `--availability online` keeps writes flowing;
`--mechanism in-place` is faster and leaves less room to recover if it is
interrupted.

## Sealing individual pieces of data

Separate from the barrier — this uses the backend's own mechanism:

```
xkmsctl can-seal --backend tpm2
xkmsctl seal "secret payload" --backend tpm2
xkmsctl unseal "$SEALED"
```

TPM sealing here is PCR-bound: the data unseals only on a machine in the same
measured state.

Sealing belongs to your tenant. With `--key-id`, the key must be one of your
tenant's keys; another tenant's key reads as "key not found". Without it, a
software, PKCS#11 or cloud-KMS backend uses your tenant's own default sealing
key, created the first time you seal, so another tenant cannot unseal your
data even with the sealed blob in hand. A tenant account cannot seal on a TPM
2.0 backend: TPM-sealed data unseals for anyone who holds it, so only
platform accounts may use it.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| everything returns "sealed" | the barrier is closed | `barrier unseal` |
| `barrier status` says sealed after a reboot | normal | unseal it, or automate unsealing |
| a `tpm2` barrier will not unseal after a firmware or boot change | the PCRs no longer match | this is the mechanism working; you need the recovery path |
| "already initialized" | there is already a root key | `rekey` replaces it; `init` will not |
| shares rejected | fewer than M, or shares from a different init | you need M shares from **this** barrier |
| old shares stopped working | someone ran `rekey` | redistribute the new ones |
| a cloud-strategy barrier will not unseal | the provider is unreachable or credentials expired | fix the **server's** environment |
| you have no credential and no recovery keys | there is no way in | the root key is unrecoverable — this is what a barrier is |

That last row is not a bug. Plan for it before you need it: generate recovery
keys, or use Shamir with enough holders, and make sure the shares are not all in
one place.

## Where to go next

- The hardware behind the strategy: [`../crypto-backends/user.md`](../crypto-backends/user.md)
- PINs and lockout: [`../pin-management/user.md`](../pin-management/user.md)
- Distributing and collecting shares: [`../share-custody/user.md`](../share-custody/user.md)
- First-boot setup: [`../init-ceremony/user.md`](../init-ceremony/user.md)
