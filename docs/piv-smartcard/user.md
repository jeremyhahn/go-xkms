# PIV Smartcard — User Guide

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-10-09

## What PIV gives you

A card — or a TPM, or a token, or a directory pretending to be one — with
numbered slots. Each slot has a job. That structure is the whole point: other
tools that read PIV credentials expect the standard slots to hold the standard
things.

| Slot | What belongs there |
|---|---|
| `9a` | authentication — logging in as you |
| `9c` | digital signature — signing documents, non-repudiation |
| `9d` | key management — encrypting and decrypting |
| `9e` | card authentication — used **without** asking you for anything |
| `f9` | the card's own attestation certificate |
| `82`–`95` | retired key-management slots, and the right home for anything else |

**If you just need "a key on the card", use a retired slot.** Taking `9a` for a
general-purpose key breaks authentication for everything else reading the card.

## Prerequisites

- A card and a reader, a TPM, or a PKCS#11 token — whichever your server is
  configured for. The commands are the same in all three cases.
- The card or token PIN. See [`../pin-management/user.md`](../pin-management/user.md).

## See what is there

```
xkmsctl piv list -o json
```

This is the only reliable way to know what a slot holds. Start here.

## Enrolling a credential

The standard sequence — the private key is created in the slot and never leaves
it:

```
xkmsctl piv generate 9a --algorithm ecdsap256 --subject "CN=alice,O=Example"
xkmsctl piv csr 9a --subject "CN=alice,O=Example" > alice.csr
xkmsctl ca sign-csr --csr alice.csr --profile client --output alice.crt
xkmsctl piv store 9a --cert-file alice.crt
xkmsctl piv get 9a --format pem
```

## Reading and clearing

```
xkmsctl piv get    9a --format pem
xkmsctl piv export 9a --format der > auth.der
xkmsctl piv delete 9a
```

`get` and `export` return the **certificate**. There is no command that exports
a PIV private key, deliberately — if there were, the card would be a filing
cabinet rather than a credential.

## Where the slots actually live

Your server is configured for one of three backings, and you may not be able to
tell from the client:

- **`file`** — a directory. The slot model is real; the hardware guarantee is
  not. Fine for development.
- **`tpm2`** — TPM non-volatile storage. Real hardware protection, and finite:
  NV space can run out.
- **`pkcs11`** — objects on a token. Real hardware protection, and subject to
  the token's PIN and lockout rules.

If a deployment claims hardware-backed PIV, confirm which one — the commands
look identical and the guarantee does not.

## What `attest_level` means when you log in with a card

Logging in with `POST /api/v1/auth/login/piv` (see
[`../auth-factors/user.md`](../auth-factors/user.md)) mints a token carrying
an `attest_level` claim, so anything that reads the token can tell how much
the login actually proved:

| `attest_level` | What it means |
|---|---|
| `hardware` | Either the server itself recorded this key as hardware-backed when it was enrolled (a PIV slot generated on a TPM or a PKCS#11 token), or the certificate you presented chained to the server's configured attestation anchor and proved it for this login. |
| `software` | The server recorded this key as software-backed when it was enrolled. Not a failure — some deployments knowingly issue software PIV credentials — but it is not a hardware guarantee, and a consumer that refuses non-hardware logins refuses this one too. |
| `unattested` | Nothing proved either way. No enrollment record was found for this key, and the certificate chain proved nothing about hardware backing either. The server had to be configured to accept this (`allow_unattested`), or the login would have been refused outright. |

You cannot upgrade a login's `attest_level` by presenting a better attestation
chain than the one your key was actually enrolled with: if the server
recorded your key's level when you enrolled it, that recorded level is what
the token gets, regardless of what the certificate chain in front of it can
or cannot prove on any given login. A recorded `hardware` is never downgraded
by a missing chain either — you do not need to keep re-presenting attestation
material on every login once the level is on record.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "invalid slot" | not one of the defined PIV slots | use `9a`, `9c`, `9d`, `9e`, `f9`, or `82`–`95` |
| slot empty | nothing stored there | `xkmsctl piv list` shows what is occupied |
| slot already occupied on generate | there is already a key there | delete it deliberately, or pick a retired slot |
| PIN required | the card or token is locked | see the PIN guide — and check lockout before retrying |
| device unavailable | no reader, no card, or the server cannot see the token | server-side hardware |
| NV space exhausted | the TPM has no room for another certificate | free a slot, or reconsider the NV base index |
| other PIV tools stopped recognising the card | something took a standard slot | move it to a retired slot |
| the attestation certificate in `f9` "proves" nothing | it was never chain-verified | verify it against the manufacturer chain |
| attestation fails on a slot that clearly holds a certificate | the key was **imported**, and an imported key cannot be attested | expected — generate the key in the slot if you need attestation |
| an attestation does not prove the key is unique to this card | this backend does not record how the key arrived | only the software (PKCS#8) backend records provenance today; a hardware backend's attestation still proves residency, not exclusivity |

## Where to go next

- PINs and lockouts: [`../pin-management/user.md`](../pin-management/user.md)
- Getting the CSR signed: [`../certificate-authority/user.md`](../certificate-authority/user.md)
- Using the card to log in: [`../auth-factors/user.md`](../auth-factors/user.md)
- The desktop companion's PIV surface: [`../../xkey/docs/`](../../xkey/docs/README.md)
