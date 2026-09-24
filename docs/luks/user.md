# LUKS (root module) — User Guide

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-24

## Is this the document you want?

If you are looking for how to create, unlock, or wipe an encrypted `xkey`
data directory, this is the wrong document — see
[`../../xkey/docs/luks/user.md`](../../xkey/docs/luks/user.md) and the
`xkey luks2` commands it describes. That is the LUKS implementation actually
running on a machine today.

This document is about `go-xkms/pkg/luks`, a Go library package in the root
module. It has no CLI, no REST/gRPC API, and no configuration file surface
(see [`cli.md`](cli.md) and [`api.md`](api.md)) — there is nothing here for
an end user or operator to run. It is consumed only by embedding it in Go
code.

## Using it as a library

Two independent pieces, used separately:

**Volume lifecycle**, once you have written an `Executor` that drives your
platform's `cryptsetup`/`dmsetup`/mount (none ships in this repository today
— see [`architecture.md`](architecture.md#volume-lifecycle-manager--executor)):

```go
mgr, err := luks.NewFIPSAwareManager("/data/vault.luks", "/mnt/vault", "xkms-vault", myExecutor)
if err != nil {
    // ErrNilExecutor, or a VolumeConfig validation error
}
if err := mgr.Create(ctx, 10<<30, passphrase); err != nil {
    // ErrInvalidSize, ErrEmptyPassphrase, or ErrOperationFailed wrapping the executor's error
}
if err := mgr.Unlock(ctx, passphrase); err != nil {
    // ...
}
defer mgr.Lock(ctx)
```

`NewFIPSAwareManager` picks Argon2id or PBKDF2-HMAC-SHA256 for you based on
the process's FIPS 140 state (`crypto/fips140.Enabled()`) — you do not
choose the KDF unless you build a `VolumeConfig` yourself and set `KDF`
explicitly.

**TPM-sealed passphrase**, independent of the above — generate and protect a
passphrase against a TPM 2.0, then hand the result to whatever adds it as a
LUKS keyslot:

```go
sealer, err := luks.NewTPMSealer(logger, luks.DefaultTPMOpener())
if err != nil {
    // ErrTPMNoTransport — no TPM device and no opener supplied
}
result, err := sealer.SealPassphrase(ctx, "", []int32{7}) // bind to PCR 7
if err != nil {
    // ErrTPMPolicyFailed / ErrTPMSealFailed
}
defer result.Passphrase.Destroy() // required — see engineering.md
// result.Passphrase.WithBytes(...) to use the raw passphrase;
// result.TokenJSON is the systemd-tpm2-shaped LUKS2 token payload to persist.
```

Later, to recover the passphrase (e.g. at boot, once the PCRs are back in
the same state used to seal):

```go
passphrase, err := sealer.UnsealPassphrase(ctx, storedTokenJSON)
if err != nil {
    // ErrTPMUnsealFailed — most commonly a PCR state mismatch; ErrTPMInvalidToken for a corrupt token
}
```

There is no PIN involved in either direction: sealing and unsealing are
gated entirely by the PCR selection given to `SealPassphrase` and recorded
in the token. See [`architecture.md`](architecture.md#child-object-pcr-policy-not-a-password)
for exactly what that does and does not protect against.

## What happens if the TPM state doesn't match

`UnsealPassphrase` returns `ErrTPMUnsealFailed` and no passphrase. There is
no degraded mode that returns a partial or default passphrase — a PCR
mismatch (firmware update, boot-order change, a measured component that
changed) is a hard failure, by design (see
[`architecture.md`](architecture.md#fail-closed-behavior-verified)).
Recovering from that state is outside this package's scope: it is the
concern of whatever key-recovery or re-enrollment flow the embedding
application builds on top of `TPMSealer`.
