# LUKS (root module) — CLI

> **Status: NORMATIVE** · Feature: `luks` · Repo: `go-xkms` · Last verified: 2026-09-24

**No `xkmsctl` surface.** Verified: no case-insensitive match for `luks`
anywhere under `cmd/xkmsctl` (excluding this package's own tests, which do
not exist there — the string does not appear at all).

`pkg/luks` has no in-tree caller (see
[`architecture.md`](architecture.md#consumers)): nothing in this repository
constructs a `luks.Manager` or a `luks.TPMSealer` outside `pkg/luks`'s own
tests and the pass-through re-export in `sdk/go/luks`. There is consequently
nothing for an `xkmsctl` command to drive yet — a `luks` verb group would
have no service behind it to call.

If a LUKS volume or TPM-sealed passphrase workflow needs a CLI, the existing
precedent in this repository is `xkey luks2 *` (`xkey/pkg/luks`, a separate
implementation — see [`architecture.md`](architecture.md#neighboring-packages-named-luks-out-of-scope-here)).
Its full command reference is
[`../../xkey/docs/luks/cli.md`](../../xkey/docs/luks/cli.md).
