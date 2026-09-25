# Signing — User Guide

> **Status: NORMATIVE** · Feature: `signing` · Repo: `go-xkms` · Last verified: 2026-09-23

## When to use this

You sign a blob you will hand out under a stable name — a release artifact, a
config version, a policy document — and you want a later `Verify` call to
catch a case where the bytes offered under that name are not the bytes you
originally signed, even if they happen to carry a valid signature from the
same key.

Without this, `Verify` only proves "this signature was produced by this key
over this digest." With `BlobCN` and `IntegrityCheck`, it additionally proves
"and this is the digest recorded when that name was signed."

## Sign a blob and record it under a name

```go
import (
    "context"
    "crypto"

    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

sig, err := xkms.Sign(context.Background(), "software:::release-signing-key", blob, &xkms.SignOptions{
    Hash:   crypto.SHA256,
    BlobCN: "release-2026.09.23",
})
if err != nil {
    log.Fatal(err)
}
```

`BlobCN` can be any stable identifier you choose; it only has to match on the
`Verify` side.

## Verify a blob against the recorded name

```go
import (
    "context"
    "crypto"

    "github.com/jeremyhahn/go-xkms/pkg/types"
    "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

err := xkms.Verify(context.Background(), "software:::release-signing-key", blob, sig, &types.VerifyOpts{
    Hash:           crypto.SHA256,
    BlobCN:         "release-2026.09.23",
    IntegrityCheck: true,
})
if err != nil {
    // Either the signature itself is invalid, or blob is not the exact
    // bytes recorded for "release-2026.09.23" -- Verify does not distinguish
    // the two in the success/failure outcome, only in the returned error type
    // (see engineering.md's Error semantics table).
    log.Fatal(err)
}
```

## Verifying without the integrity check

Leave `IntegrityCheck` unset (the default, `false`) for ordinary signature
verification with no persisted-record requirement — this is unchanged from
before this feature existed, and works whether or not the blob was ever
signed with a `BlobCN`.

## What you do not need to manage yourself

`SignerStore()` — where the digest and signature actually live — is wired up
automatically for every backend (`pkg/xkms.New`, `AutoInitialize`): you do not
construct or configure it. If you call `Verify` with `IntegrityCheck: true`
and never signed anything under that `BlobCN`, you get a typed
"not found" error (`*store.ErrSignatureNotFound`), not a silent pass and not a
crash.
