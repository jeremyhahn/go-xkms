# Sign Server — User Guide

> **Status: NORMATIVE** · Feature: `sign-server` · Repo: `go-xkms` · Last verified: 2026-10-01

## When to use it

Your daemon owns a node's keys and runs without cgo. Another program on the
same host, typically an IKE daemon, needs to sign with one of those keys
through PKCS#11. Embed the sign server, create the key, and point the other
program's PKCS#11 module at the socket.

## 1. Embed and create the key

See the example in [`engineering.md`](engineering.md#configuration-example).
Name every key the consumer may use in its slot's `Keys`, and list only the
consumer's uid in `AllowedUIDs`. `CreateKey` is idempotent: call it at every
start. A second call with the same label, id and curve returns the existing
key with `Created` false. A different key under that label or id is refused.

The first key in a token needs the SO PIN, which initializes the token and sets
the user PIN. Later keys need only the user PIN.

## 2. Configure the consumer

```
export XKMS_PKCS11_TARGET=unix:///run/<daemon>/ike.sock
export XKMS_PKCS11_STORAGE_TYPE=remote
export XKMS_PKCS11_TOKEN_LABEL=ike
export XKMS_PKCS11_DEFAULT_BACKEND=tpm2
```

Load `<install-dir>/lib/libxkms_pkcs11.so` in the consumer, log in with the
user PIN, and select the key by its `CKA_ID` or `CKA_LABEL`. Sign with
`CKM_ECDSA` over a SHA-256 or SHA-384 digest; the signature is raw `r || s`.

## 3. Serve

Call `Serve` (it blocks) and `Stop` on shutdown. The socket's directory must
be private to the daemon; `Serve` refuses a group- or world-writable one.

## Troubleshooting

| Symptom | Cause |
|---|---|
| consumer's `C_Initialize` returns `CKR_DEVICE_ERROR` | its uid is not in `AllowedUIDs`/`AllowedGIDs`, or the socket path is wrong |
| `C_FindObjects` finds nothing | wrong `XKMS_PKCS11_TOKEN_LABEL`, or the key was not created |
| `C_Sign` fails | the key's label is not in the slot's `Keys` (the server refused `Sign`) |
| `CreateKey` returns `ErrProvisionKeyConflict` | the token holds a different key under that label or id |
| `CreateKey` returns `ErrProvisionSOPINRequired` | the token is new; pass the SO PIN once |

The PIN protects the token from a process that uses the module without it. It
does not replace the uid allowlist; see
[`architecture.md`](architecture.md#pins).
