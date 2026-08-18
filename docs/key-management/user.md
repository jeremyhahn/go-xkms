# Key Management — User Guide

> **Status: NORMATIVE** · Feature: `key-management` · Repo: `go-xkms` · Last verified: 2026-08-19

## Prerequisites

- `xkmsctl` on your PATH.
- Either a running `xkmsd` you can reach, or nothing at all if you use
  `--transport embedded` (everything runs in-process against a local key
  directory).
- For a hardware backend: the device present and its PIN available. For a cloud
  backend: the provider's credentials in the environment the server runs in.

## First run, with no server

```
xkmsctl --transport embedded --key-dir ./keys key generate my-first-key
xkmsctl --transport embedded --key-dir ./keys key list
```

That is the whole setup. The key lives under `./keys`; nothing was sent
anywhere.

## Talking to a server

```
export XKMS_SERVER=https://kms.example.com:8443
xkmsctl --transport rest --server "$XKMS_SERVER" --token "$TOKEN" key list
```

If the server presents a certificate you have pinned, pass `--spki-pin`. If it
wants client certificates, pass `--tls-cert`/`--tls-key`/`--tls-ca`.

## Choosing where a key lives

`--backend` picks the store. `xkmsctl backends list` shows what this server has
configured; `xkmsctl algorithms` shows what it will accept.

```
xkmsctl backends list
xkmsctl key generate signing-key --backend tpm2 --key-algorithm ecdsa --curve P-256
```

Once created, a key stays in its backend. Moving it is `key copy`, and only
works if the source key is exportable.

## The three decisions you make once per key

1. **Algorithm** — `--key-algorithm rsa|ecdsa|ed25519`, plus `--key-size` or
   `--curve`. For symmetric keys, `--key-type symmetric --algorithm aes-256-gcm`.
2. **Exportable or not** — `--exportable` lets you get the material back out
   later. Without it, export is refused.
3. **Sensitive or not** — `--sensitive` refuses export permanently, by every
   path, forever. There is no undo. Use it for keys that must never leave.

## Everyday tasks

**Sign and verify**

```
xkmsctl key sign signing-key "$(base64 -w0 message.bin)" --hash sha256
xkmsctl key verify signing-key "$(base64 -w0 message.bin)" "$SIGNATURE" --hash sha256
```

**Encrypt something small with a symmetric key**

```
xkmsctl key generate app-dek --key-type symmetric --algorithm aes-256-gcm
xkmsctl key encrypt app-dek "secret value" --aad "app=billing"
```

Keep the nonce and tag from the output — `key decrypt` needs both, plus the same
`--aad`.

**Rotate**

```
xkmsctl key rotate signing-key
```

The key ID does not change, so nothing referring to it needs updating. Old
signatures made with the previous material still verify against material you
retained; plan rotation with that in mind.

**Move a key into the service without ever writing it to disk in the clear**

```
xkmsctl key get-import-params imported-key --output params.json
xkmsctl key wrap plaintext.key params.json wrapped.bin
xkmsctl key import imported-key wrapped.bin --key-type rsa --key-size 3072
```

**Re-wrap a key that is already in the service** (nothing is ever decrypted
outside it):

```
xkmsctl key wrap-by-id app-dek --wrapping-key master-kek --output app-dek.wrapped
```

**Prove a key was made in hardware**

```
xkmsctl key attest node-key --backend tpm2 --output attestation.json
```

What the evidence means depends on the backend — a TPM quote is not a cloud
provider's attestation document. Check the backend's own page before relying on
it.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `keystore: key not found` | the ID is right but the backend is wrong | pass the `--backend` the key was created in |
| `keystore: key already exists` | generating over an existing ID | use `key rotate`, or pick a new ID |
| export refused | the key is not `exportable`, or is `sensitive` | it cannot be exported; this is not recoverable |
| `keystore: security officer PIN required` / `user PIN required` | a hardware backend has not been unlocked | supply `--so-pin` / `--pkcs11-pin`, or set the PIN first |
| everything returns "sealed" | the barrier is closed | unseal it — see the sealing and barrier guide |
| connection refused on 8445 vs 9444 | the MCP port disagreement | set the port explicitly on both sides; see `api.md` §Port conflicts |
| `operation not supported by this protocol` | you are on the USB transport | that channel carries the phone path only |

## Where to go next

- Which backend to pick, and what each can actually do:
  [`../crypto-backends/user.md`](../crypto-backends/user.md)
- Getting keys under a barrier:
  [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- Issuing certificates for the keys you just made:
  [`../certificate-authority/user.md`](../certificate-authority/user.md)
