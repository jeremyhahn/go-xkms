# LUKS (root module) — User Guide

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-30

## Is this the document you want?

If you are looking for how to create, unlock, or wipe an encrypted `xkey`
data directory, this is the wrong document — see
[`../../xkey/docs/luks/user.md`](../../xkey/docs/luks/user.md) and the
`xkey luks2` commands it describes. `xkey` is a consumer of this package
(through `sdk/go/luks`), not a separate implementation.

This document is about `go-xkms/pkg/luks`, a Go library package in the root
module. It has no CLI, no REST/gRPC API, and no configuration file surface
(see [`cli.md`](cli.md) and [`api.md`](api.md)) — there is nothing here for
an end user or operator to run. It is consumed only by embedding it in Go
code, through the `sdk/go/luks` re-export.

## Using it as a library

Two independent pieces, used separately:

**Volume lifecycle**, backed by the production, `go-luks2`-based `Executor`:

```go
import sdkluks "github.com/jeremyhahn/go-xkms/sdk/go/luks"

mgr, err := sdkluks.NewFIPSAwareManager("/data/vault.luks", "/mnt/vault", "xkms-vault", sdkluks.NewLibExecutor())
if err != nil {
    // ErrNilExecutor, or a VolumeConfig validation error
}
if err := mgr.Create(ctx, 10<<30, passphrase); err != nil {
    // ErrInvalidSize, ErrEmptyPassphrase, or ErrOperationFailed wrapping
    // the executor's error (e.g. ErrVolumeAlreadyExists)
}
if err := mgr.Unlock(ctx, passphrase); err != nil {
    // ...
}
if err := mgr.Mount(ctx); err != nil {
    // ...
}
defer mgr.Lock(ctx)
```

`NewFIPSAwareManager` picks Argon2id or PBKDF2-HMAC-SHA256 for you based on
the process's FIPS 140 state (`crypto/fips140.Enabled()`) — you do not
choose the KDF unless you build a `VolumeConfig` yourself and set `KDF`
explicitly. A long-lived process (a daemon) should build one `Manager` and
keep it for the volume's lifetime; a one-call-per-invocation CLI should
drive the `Executor` directly instead (`sdkluks.NewLibExecutor()`,
`sdkluks.IsMounted`/`IsUnlocked`) — see
[`architecture.md`](architecture.md#manager-is-per-process-not-per-host).

**TPM-sealed passphrase**, independent of the above — generate and protect a
passphrase against a TPM 2.0, then hand the result to whatever adds it as a
LUKS keyslot. The storage parent is explicit:

```go
// Default: the Platform SRK, bound to go-xkms's platform PCR policy.
sealer, err := sdkluks.NewTPMSealer(myTPM2 /* *pkg/tpm2.TPM2 */, sdkluks.TPMSealerConfig{})
if err != nil {
    // ErrTPMNoTransport (nil tpm), *SealParentInvalidError, ErrInvalidPCRBank
}
result, err := sealer.SealPassphrase(ctx, nil) // no PCR argument: the platform policy owns the PCR set
if err != nil {
    // ErrTPMSealFailed
}
defer result.Passphrase.Destroy() // required — see engineering.md
// result.Passphrase.WithBytes(...) to use the raw passphrase;
// result.Token is the LUKS2 token (go-luks2.Token) to persist via
// go-luks2.ImportToken, after result.Token.Keyslots is filled in.
```

```go
// Opt-in: the Shared SRK, for systemd-cryptsetup boot-time unlock.
sealer, err := sdkluks.NewTPMSealer(myTPM2, sdkluks.TPMSealerConfig{
    Parent:  sdkluks.SealParentSSRK,
    PCRBank: "sha256",
})
result, err := sealer.SealPassphrase(ctx, []int32{7}) // bind to PCR 7, systemd-cryptenroll's convention
```

To recover a `SealParentPSRK` passphrase (e.g. at boot, once the PCRs are
back in the same state used to seal):

```go
passphrase, err := sealer.UnsealPassphrase(ctx, storedToken)
if err != nil {
    // ErrTPMUnsealFailed — most commonly a PCR state mismatch; ErrTPMInvalidToken for a corrupt token
}
```

A `SealParentSSRK` token is **not** unsealed through this package —
`UnsealPassphrase` on an SSRK-configured sealer always returns
`ErrTPMSSRKUnsealUnsupported`. That token is meant for
`systemd-cryptenroll`/crypttab to unseal at boot, outside go-xkms entirely;
see [`architecture.md`](architecture.md#tpmsealerunsealpassphrase-refuses-an-ssrk-token)
for why.

## Choosing a `SealParent`

| | `SealParentPSRK` (default) | `SealParentSSRK` |
|---|---|---|
| Parent key | go-xkms's Platform SRK | TCG Shared SRK (`0x81000001`) |
| Parent auth | USER PIN (platform policy) | empty (TCG default) |
| PCR policy | go-xkms's platform policy (fixed PCR set) | caller-chosen PCR selection |
| Who can unseal | go-xkms itself (`UnsealPassphrase`) | `systemd-cryptsetup` only |
| Boot-time unlock | go-xkms's own auto-unseal path | `systemd-cryptenroll`/crypttab |
| go-xkms#681 PSRK-only rule | follows it | documented, narrow exception |

Pick `SealParentPSRK` unless the volume specifically needs
`systemd-cryptenroll`/crypttab to unlock it at boot without go-xkms running.

## What happens if the TPM state doesn't match

`UnsealPassphrase` returns `ErrTPMUnsealFailed` and no passphrase. There is
no degraded mode that returns a partial or default passphrase — a PCR
mismatch (firmware update, boot-order change, a measured component that
changed) is a hard failure, by design (see
[`architecture.md`](architecture.md#fail-closed-behavior-verified)).
Recovering from that state is outside this package's scope: it is the
concern of whatever key-recovery or re-enrollment flow the embedding
application builds on top of `TPMSealer`.
